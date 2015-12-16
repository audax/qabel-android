package de.qabel.qabelbox.storage;

import android.test.AndroidTestCase;
import android.util.Log;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.mobileconnectors.s3.transferutility.TransferUtility;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.DeleteObjectsRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.S3ObjectSummary;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import de.qabel.core.crypto.CryptoUtils;
import de.qabel.core.crypto.QblECKeyPair;
import de.qabel.qabelbox.R;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

/**
 * Created by cdemon on 15.12.2015.
 */
public class SearchTest extends AndroidTestCase {

    private final static String TAG = SearchTest.class.getName();

    //will represent a filled resultset after setUp()
    //
    //level0-one.bin
    //+dir1-level1-one
    //  level1-ONE.bin
    //  level1-two-Small.bin
    //  +dir1-level2-one
    //      one-level2-one.bin
    //  +dir1-level2-two
    //      two-level2-one.bin
    //
    private static List<BoxObject> searchResults;

    private static boolean setup = true;

    public void setUp() throws Exception {
        if (!setup) {
            //setting up the directory structure takes time and so it is only made once - @AfterClass is not available here, so the cleanup is done, too
            return;
        }

        setup = false;

        AmazonS3Client s3Client = null;
        final String bucket = "qabel";
        final String prefix = UUID.randomUUID().toString();

        try {
            CryptoUtils utils = new CryptoUtils();
            byte[] deviceID = utils.getRandomBytes(16);
            QblECKeyPair keyPair = new QblECKeyPair();

            AWSCredentials awsCredentials = new AWSCredentials() {
                @Override
                public String getAWSAccessKeyId() {
                    return getContext().getResources().getString(R.string.aws_user);
                }

                @Override
                public String getAWSSecretKey() {
                    return getContext().getString(R.string.aws_password);
                }
            };
            AWSCredentials credentials = awsCredentials;
            s3Client = new AmazonS3Client(credentials);
            assertNotNull(awsCredentials.getAWSAccessKeyId());
            assertNotNull(awsCredentials.getAWSSecretKey());

            TransferUtility transfer = new TransferUtility(s3Client, getContext());
            BoxVolume volume = new BoxVolume(transfer, credentials, keyPair, bucket, prefix,
                    deviceID, getContext());

            volume.createIndex(bucket, prefix);

            Log.d(TAG, "VOL :" + volume.toString());

            BoxNavigation nav = volume.navigate();

            setupFakeDirectoryStructure(nav);

            setupBaseSearch(nav);
        } finally {
            if (s3Client != null) {
                cleanUp(s3Client, bucket, prefix);
            }
        }

        Log.d(TAG, "SETUP DONE");
    }

    public void cleanUp(AmazonS3Client s3Client, String bucket, String prefix) throws IOException {
        ObjectListing listing = s3Client.listObjects(bucket, prefix);
        List<DeleteObjectsRequest.KeyVersion> keys = new ArrayList<>();

        for (S3ObjectSummary summary : listing.getObjectSummaries()) {
            Log.d(TAG, "DELETE: " + summary.getKey());
            keys.add(new DeleteObjectsRequest.KeyVersion(summary.getKey()));
        }

        if (keys.isEmpty()) {
            return;
        }

        DeleteObjectsRequest deleteObjectsRequest = new DeleteObjectsRequest(bucket);
        deleteObjectsRequest.setKeys(keys);
        s3Client.deleteObjects(deleteObjectsRequest);
    }

    private void setupFakeDirectoryStructure(BoxNavigation nav) throws Exception {

        String testFile = BoxTest.createTestFile();
        String smallFile = BoxTest.smallTestFile().getAbsolutePath();

        assertThat(nav.listFiles().size(), is(0));

        nav.upload("level0-one.bin", new FileInputStream(testFile), null);
        nav.commit();

        BoxFolder folder = nav.createFolder("dir1-level1-one");
        nav.commit();
        nav.navigate(folder);

        nav.upload("level1-ONE.bin", new FileInputStream(testFile), null);
        nav.commit();
        nav.upload("level1-two-Small.bin", new FileInputStream(smallFile), null);
        nav.commit();

        folder = nav.createFolder("dir1-level2-one");
        nav.commit();
        nav.navigate(folder);

        nav.upload("one-level2-one.bin", new FileInputStream(testFile), null);
        nav.commit();

        nav.navigateToParent();

        folder = nav.createFolder("dir1-level2-two");
        nav.commit();
        nav.navigate(folder);

        nav.upload("two-level2-one.bin", new FileInputStream(testFile), null);
        nav.commit();

        while (nav.hasParent()) {
            nav.navigateToParent();
        }

        Log.d(TAG, "NAV : " + nav);

        debug(nav);

    }

    private void debug(BoxNavigation nav) throws Exception {

        for (BoxFile file : nav.listFiles()) {
            Log.d(TAG, "FILE: " + file.name);
        }

        for (BoxFolder folder : nav.listFolders()) {
            Log.d(TAG, "DIR : " + folder.name);

            nav.navigate(folder);
            debug(nav);
            nav.navigateToParent();
        }
    }

    private void debug(BoxObject o) {
        if (o instanceof BoxFile) {
            Log.d(TAG, "FILE: " + o.name + " @" + ((BoxFile) o).size);
        }
        else {
            Log.d(TAG, "DIR : " + o.name);
        }
    }

    private void setupBaseSearch(BoxNavigation nav) throws Exception {
        searchResults = new StorageSearch(nav).getResults();
    }

    @Test
    public void testCollectAll() throws Exception {

        Log.d(TAG, "collectAll");

        for (BoxObject o : searchResults) {
            debug(o);
        }

        assertEquals(8, searchResults.size());

        Log.d(TAG, "/collectAll");
    }

    @Test
    public void testForValidName() throws Exception {
        assertFalse(StorageSearch.isValidSearchTerm(null));
        assertFalse(StorageSearch.isValidSearchTerm(""));
        assertFalse(StorageSearch.isValidSearchTerm(" "));

        assertTrue(StorageSearch.isValidSearchTerm("1"));
    }

    @Test
    public void testNameSearch() throws Exception {
        List<BoxObject> lst = new StorageSearch(searchResults).filterByName("small").getResults();

        assertEquals(1, lst.size());
        assertEquals("level1-two-Small.bin", lst.get(0).name);

        StorageSearch search = new StorageSearch(searchResults).filterByNameCaseSensitive("small");
        assertEquals(0, search.getResults().size());

        search =  new StorageSearch(searchResults).filterByNameCaseSensitive("Small");
        assertEquals(1, search.getResults().size());

        //if not valid don't apply the filter
        search =  new StorageSearch(searchResults).filterByName(null);
        assertEquals(8, search.getResults().size());

        search = new StorageSearch(searchResults).filterByName("");
        assertEquals(8, search.getResults().size());

        search = new StorageSearch(searchResults).filterByName(" ");
        assertEquals(8, search.getResults().size());
    }

    @Test
    public void testFilterBySize() throws Exception {

        StorageSearch search = new StorageSearch(searchResults).filterByNameCaseSensitive("level1");
        assertEquals(3, search.getResults().size());

        search = new StorageSearch(searchResults).filterByNameCaseSensitive("level1")
                .filterByMaximumSize(100);
        assertEquals(1, search.getResults().size());

        search = new StorageSearch(searchResults).filterByNameCaseSensitive("level1")
                .filterByMaximumSize(110000);
        assertEquals(2, search.getResults().size());

        search = new StorageSearch(searchResults).filterByNameCaseSensitive("level1")
                .filterByMaximumSize(100000);
        assertEquals(1, search.getResults().size());

        search = new StorageSearch(searchResults).filterByNameCaseSensitive("level1")
                .filterByMinimumSize(1);
        assertEquals(2, search.getResults().size());

        search = new StorageSearch(searchResults).filterByNameCaseSensitive("level1")
                .filterByMinimumSize(100);
        assertEquals(1, search.getResults().size());

        search = new StorageSearch(searchResults).filterByNameCaseSensitive("level1")
                .filterByMinimumSize(10000000);
        assertEquals(0, search.getResults().size());
    }

    @Test
    public void testFilterByFileOrDir() throws Exception {

        List<BoxObject> objs = new StorageSearch(searchResults).filterByNameCaseSensitive("level1")
                .filterOnlyDirectories().getResults();
        assertEquals(1, objs.size());

        List<BoxFolder> dirs = StorageSearch.toBoxFolders(objs);
        assertEquals(1, dirs.size());
        assertEquals("dir1-level1-one", dirs.get(0).name);

        objs = new StorageSearch(searchResults).filterByNameCaseSensitive("level1")
                .filterOnlyFiles().getResults();
        assertEquals(2, objs.size());

        List<BoxFile> files = StorageSearch.toBoxFiles(objs);
        assertEquals(2, files.size());
        assertEquals("level1-ONE.bin", files.get(0).name);
        assertEquals("level1-two-Small.bin", files.get(1).name);
    }


}
