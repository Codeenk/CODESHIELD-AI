// Deliberately vulnerable sample — used by the demo and tests.
import java.sql.Statement;
import java.io.ObjectInputStream;

public class App {
    private String dbPassword = "SuperSecret123";
    private Statement stmt;

    public java.sql.ResultSet getUser(String id) throws Exception {
        // SQL injection via string concatenation
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    public Object restore(byte[] data) throws Exception {
        // Insecure deserialization
        return new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(data)).readObject();
    }
}
