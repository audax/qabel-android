package de.qabel.desktop.repository.sqlite;

import de.qabel.desktop.repository.EntityManager;
import org.junit.After;
import org.junit.Before;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public abstract class AbstractSqliteRepositoryTest<T> {
    protected Connection connection;
    protected ClientDatabase clientDatabase;
    protected T repo;
    protected EntityManager em;

    @Before
    public void setUp() throws Exception {
        connection = DriverManager.getConnection("jdbc:sqlite::memory:");
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA FOREIGN_KEYS = ON");
        }
        clientDatabase = new DesktopClientDatabase(connection);
        clientDatabase.migrate();
        em = new EntityManager();
        repo = createRepo(clientDatabase, em);
    }

    protected abstract T createRepo(ClientDatabase clientDatabase, EntityManager em) throws Exception;

    @After
    public void tearDown() throws Exception {
        connection.close();
    }
}