/*
 * Copyright (C) 2012 jonas.oreland@gmail.com
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.runnerup.export.oauth2client;

import android.annotation.SuppressLint;
import android.app.ProgressDialog;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.view.Window;
import androidx.appcompat.app.AppCompatActivity;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.runnerup.common.util.Constants.DB;
import org.runnerup.export.Synchronizer;
import org.runnerup.export.util.FormValues;
import org.runnerup.export.util.SyncHelper;
import org.runnerup.util.ViewUtil;

@SuppressLint("SetJavaScriptEnabled")
public class OAuth2Activity extends AppCompatActivity {

  /** Names used in Bundle to/from OAuth2Activity */
    public interface OAuth2ServerCredentials {

        String AUTH_ARGUMENTS = "auth_arguments";

        /** Used as title when opening authorization dialog */
        String NAME = "name";

        String CLIENT_ID = "client_id";
        String CLIENT_SECRET = "client_secret";
        String AUTH_URL = "auth_url";
        String AUTH_EXTRA = "auth_extra";
        String TOKEN_URL = "token_url";
        String REDIRECT_URI = "redirect_uri";
    }

    private boolean mFinished = false;
    private String mRedirectUri = null;
    private Bundle mArgs = null;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();


    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent intent = getIntent();
        Bundle b = mArgs = intent.getBundleExtra(OAuth2ServerCredentials.AUTH_ARGUMENTS);
        if (b == null) {
            finish();
            return;
        }
        String auth_url = b.getString(OAuth2ServerCredentials.AUTH_URL);
        String client_id = b.getString(OAuth2ServerCredentials.CLIENT_ID);
        mRedirectUri = b.getString(OAuth2ServerCredentials.REDIRECT_URI);
        String auth_extra = null;
        if (b.containsKey(OAuth2ServerCredentials.AUTH_EXTRA))
            auth_extra = b.getString(OAuth2ServerCredentials.AUTH_EXTRA);

        Uri.Builder tmp = Uri.parse(auth_url).buildUpon()
                .appendQueryParameter("client_id", client_id)
                .appendQueryParameter("response_type", "code")
                .appendQueryParameter("redirect_uri", mRedirectUri);
        if (auth_extra != null) {
            for (String kv : auth_extra.split("&")) {
                String[] parts = kv.split("=");
                if (parts.length == 2) {
                    tmp.appendQueryParameter(parts[0], parts[1]);
                }
            }
        }

        Intent browserIntent = new Intent(Intent.ACTION_VIEW, tmp.build());
        startActivity(browserIntent);

        // This activity will be reopened by the redirect
        finish();
    }

    @Override
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleRedirect(intent);
    }

    @Override
    public void onResume() {
        super.onResume();
        handleRedirect(getIntent());
    }

    private void handleRedirect(Intent intent) {
        if (mFinished) return;

        Uri u = intent.getData();
        if (u == null) return;

        if (!u.toString().startsWith(mRedirectUri)) return;

        String e = null;
        e = u.getQueryParameter("error");

        if (e != null) {
            Log.d(getClass().getName(), "e: " + e);
            Intent res = new Intent().putExtra("error", e);
            setResult(RESULT_CANCELED, res);
            mFinished = true;
            finish();
            return;
        }

        String code = u.getQueryParameter("code");
        if (code != null) {
            mFinished = true;
            exchangeCodeForToken(u);
        }
    }

  private void exchangeCodeForToken(Uri uri) {
    Bundle b = mArgs;
    String code = uri.getQueryParameter("code");
    final String token_url = b.getString(OAuth2ServerCredentials.TOKEN_URL);
    final FormValues fv = new FormValues();
    fv.put("client_id", b.getString(OAuth2ServerCredentials.CLIENT_ID));
    fv.put("client_secret", b.getString(OAuth2ServerCredentials.CLIENT_SECRET));
    fv.put("grant_type", "authorization_code");
    fv.put("redirect_uri", b.getString(OAuth2ServerCredentials.REDIRECT_URI));
    fv.put("code", code);

    final Intent res = new Intent().putExtra("url", token_url);
    final Handler handler = new Handler(Looper.getMainLooper());

    executor.execute(
        () -> {
          int resultCode = AppCompatActivity.RESULT_CANCELED;
          HttpURLConnection conn = null;

          try {
            URL newUrl = new URL(token_url);
            conn = (HttpURLConnection) newUrl.openConnection();
            conn.setDoOutput(true);
            conn.setRequestMethod(Synchronizer.RequestMethod.POST.name());
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            SyncHelper.postData(conn, fv);
            StringBuilder obj = new StringBuilder();
            int responseCode = conn.getResponseCode();
            String amsg = conn.getResponseMessage();

            try {
              BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
              char[] buf = new char[1024];
              int len;
              while ((len = in.read(buf)) != -1) {
                obj.append(buf, 0, len);
              }

              res.putExtra(DB.ACCOUNT.AUTH_CONFIG, obj.toString());
              if (responseCode >= HttpURLConnection.HTTP_OK
                  && responseCode < HttpURLConnection.HTTP_MULT_CHOICE) {
                resultCode = AppCompatActivity.RESULT_OK;
              }
            } catch (IOException e) {
              InputStream inS = conn.getErrorStream();
              String msg = inS == null ? "" : SyncHelper.readInputStream(inS);
              Log.w("oath2", "Error stream: " + responseCode + " " + amsg + "; " + msg);
            }
          } catch (Exception ex) {
            ex.printStackTrace(System.err);
            res.putExtra("ex", ex.toString());
          } finally {
            if (conn != null) {
              conn.disconnect();
            }
          }

          final int finalResultCode = resultCode;
          handler.post(
              () -> {
                setResult(finalResultCode, res);
                finish();
              });
        });
    }

    @Override
    public void onDestroy() {
    if (executor != null) {
        executor.shutdown();
    }
        super.onDestroy();
    }

    public static Intent getIntent(AppCompatActivity activity, OAuth2Server server) {
        Bundle b = new Bundle();
        b.putString(OAuth2ServerCredentials.CLIENT_ID, server.getClientId());
        b.putString(OAuth2ServerCredentials.CLIENT_SECRET, server.getClientSecret());
        b.putString(OAuth2ServerCredentials.AUTH_URL, server.getAuthUrl());
        b.putString(OAuth2ServerCredentials.TOKEN_URL, server.getTokenUrl());
        b.putString(OAuth2ServerCredentials.REDIRECT_URI, server.getRedirectUri());
        String extra = server.getAuthExtra();
        if (extra != null) {
            b.putString(OAuth2ServerCredentials.AUTH_EXTRA, extra);
        }

        return new Intent(activity, OAuth2Activity.class)
                .putExtra(OAuth2ServerCredentials.AUTH_ARGUMENTS, b);
    }
}
