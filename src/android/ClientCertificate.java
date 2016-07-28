package org.apache.cordova.plugin.clientcert;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Environment;
import android.preference.PreferenceManager;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.util.Log;
import android.widget.Toast;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.ICordovaClientCertRequest;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Arrays;
import java.util.Enumeration;
import java.io.FileInputStream;
import java.io.InputStream;

@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class ClientCertificate extends CordovaPlugin {


    private static final int ERROR_NO_CERTIFICATE_FOUND = 0;
    private static final int EXCEPTION_FOUND = 1;
    private static final String ERROR_0_MESSAGE = "No certificate found.";
    public String p12path = "";
    public String p12password = "";


    @Override
    public Boolean shouldAllowBridgeAccess(String url) {
        return super.shouldAllowBridgeAccess(url);
    }
    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);

    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {
        try {

        } catch (Exception ex)
        {
            request.ignore();
        }
        return true;
    }

    @Override
    public boolean execute(String action, JSONArray a, CallbackContext cordovaCallback) throws JSONException {
        if (action.equals("registerAuthenticationCertificate"))
        {
            p12path = a.getString(0);
            p12password = a.getString(1);
            readCertificate(cordovaCallback);
        }
        return false;
    }

    private void readCertificate(CallbackContext cordovaCallback){
        try {
            KeyStore p12 = KeyStore.getInstance("PKCS12");
            File p12File = null;
            File file = new File(p12path);
            if(file.isDirectory()){
                File[] files = file.listFiles(new FilenameFilter() {
                    public boolean accept(File dir, String name) {
                        return name.toLowerCase().endsWith(".p12");
                    }
                });
                for(int i=0;i<files.length;i++){
                    if(files[i].isFile()){
                        p12File = new File(file,files[i].getName());
                        break;
                    }
                }
            }else{
                p12File =  file;
            }

            InputStream astream = new FileInputStream(p12File);

            //cordova.getActivity().getApplicationContext().getAssets().open(p12path);
            p12.load(astream, p12password.toCharArray());
            Enumeration e = p12.aliases();

            JSONObject jsonObject = new JSONObject();
            while (e.hasMoreElements()) {

                String alias = (String) e.nextElement();
                X509Certificate c = (X509Certificate) p12.getCertificate(alias);
                if(c.getBasicConstraints() >0) {
                    continue;
                }
                jsonObject.put("basicConstraints",c.getBasicConstraints());
                jsonObject.put("issuerAlternativeNames",c.getIssuerAlternativeNames());
                jsonObject.put("extendedKeyUsage",c.getExtendedKeyUsage());
                jsonObject.put("issuerDN",c.getIssuerDN().toString());
                jsonObject.put("issuerUniqueID",c.getIssuerUniqueID());
                jsonObject.put("validTo",c.getNotAfter().getTime());
                jsonObject.put("serialNumber",c.getSerialNumber().toString());
                jsonObject.put("sigAlgOID",c.getSigAlgOID());
                jsonObject.put("signature",c.getSignature().toString());
                jsonObject.put("subjectDN",c.getSubjectDN());
                jsonObject.put("version",c.getVersion());
                jsonObject.put("type",c.getType());
                jsonObject.put("validFrom",c.getNotBefore().getTime());
                Principal subject = c.getSubjectDN();
                String subjectArray[] = subject.toString().split(",");
                for (String s : subjectArray) {
                    String[] str = s.trim().split("=");
                    String key = str[0];
                    String value = str[1];
                    //System.out.println(key + " - " + value);
                    jsonObject.put(key,value);
                }
                // jsonArray.put(jsonObject);
                break;
            }
            cordovaCallback.success(jsonObject.getString("CN"));
        } catch (CertificateException e) {
            exceptionMessageInErrorCallback(cordovaCallback, e);
        } catch (NoSuchAlgorithmException e) {
            exceptionMessageInErrorCallback(cordovaCallback, e);
        } catch (KeyStoreException e) {
            exceptionMessageInErrorCallback(cordovaCallback, e);
        } catch (JSONException e) {
            exceptionMessageInErrorCallback(cordovaCallback, e);
        }  catch (IOException e) {
            exceptionMessageInErrorCallback(cordovaCallback,e);
        } catch (Exception ex){
            cordovaCallback.error(createErrorObject(ERROR_NO_CERTIFICATE_FOUND, ERROR_0_MESSAGE).toString());
        }
    }

    private void exceptionMessageInErrorCallback(CallbackContext cordovaCallback, Exception e){
        try {
            JSONObject jsonObject = createErrorObject(EXCEPTION_FOUND, e.getMessage());
            jsonObject.put("Exception", e.toString());
            cordovaCallback.error(jsonObject.toString());
        }catch (Exception ex){

        }
    }

    private JSONObject createErrorObject(int code, String message) {
        JSONObject obj = new JSONObject();
        try {
            obj.put("code", code);
            obj.put("message", message);
        } catch (JSONException e) {
            // This will never happen
        }
        return obj;
    }


}