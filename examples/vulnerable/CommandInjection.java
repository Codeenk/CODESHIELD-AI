// Example: OS command injection (CWE-78). Intentionally vulnerable — do not deploy.

public class CommandInjection {

    public String ping(String host) throws Exception {
        // Vulnerable: untrusted host is executed via the shell.
        Runtime.getRuntime().exec("ping -c 1 " + host);
        return "done";
    }
}
