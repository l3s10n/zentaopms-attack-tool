package fun.fireline.core;

import fun.fireline.controller.MainController;
import fun.fireline.tools.Tools;
import javafx.concurrent.Task;

/**
 * @author yhy
 * @date 2021/8/21 14:33
 * @github https://github.com/yhy0
 */

public class VulCheckTask extends Task<Void> {
    private String target;
    private String vulName;
    private String result;
    public static ExploitInterface ei;

    public VulCheckTask(String target, String vulName) {
        this.target = target;
        this.vulName = vulName;
    }

    protected Void call() {
        ei = Tools.getExploit(vulName);
        String result = ei.checkVul(this.target);
        this.updateMessage(result);
        this.setResult(result);
        return null;
    }

    public String getResult() {
        return this.result;
    }

    public void setResult(String result) {
        this.result = result;
    }
}
