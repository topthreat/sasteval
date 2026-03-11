using System.Data.SQLite;

namespace SastEval.Util;

public static class DbUtil
{
    private static SQLiteConnection? _connection;

    public static SQLiteConnection GetConnection()
    {
        if (_connection == null)
        {
            _connection = new SQLiteConnection("Data Source=:memory:");
            _connection.Open();
            InitSchema();
        }
        return _connection;
    }

    private static void InitSchema()
    {
        var conn = _connection!;

        using var cmdUsers = new SQLiteCommand(@"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                email TEXT,
                password TEXT,
                role TEXT
            )", conn);
        cmdUsers.ExecuteNonQuery();

        using var cmdProducts = new SQLiteCommand(@"
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT,
                description TEXT,
                price REAL
            )", conn);
        cmdProducts.ExecuteNonQuery();

        using var cmdOrders = new SQLiteCommand(@"
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                product_id INTEGER,
                quantity INTEGER,
                status TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (product_id) REFERENCES products(id)
            )", conn);
        cmdOrders.ExecuteNonQuery();

        using var cmdComments = new SQLiteCommand(@"
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                body TEXT
            )", conn);
        cmdComments.ExecuteNonQuery();

        // Seed some test data
        using var cmdSeed = new SQLiteCommand(@"
            INSERT OR IGNORE INTO users (id, username, email, password, role) VALUES
                (1, 'alice', 'alice@example.com', 'password123', 'admin'),
                (2, 'bob', 'bob@example.com', 'hunter2', 'user'),
                (3, 'charlie', 'charlie@example.com', 'qwerty', 'user');
            INSERT OR IGNORE INTO products (id, name, description, price) VALUES
                (1, 'Widget', 'A standard widget', 9.99),
                (2, 'Gadget', 'A fancy gadget', 29.99);
        ", conn);
        cmdSeed.ExecuteNonQuery();
    }
}
