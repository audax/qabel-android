package de.qabel.qabelbox.services;

import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.security.KeyPairGeneratorSpec;
import android.security.KeyStoreParameter;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.commons.lang3.RandomStringUtils;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import de.qabel.core.config.Contact;
import de.qabel.core.config.Contacts;
import de.qabel.core.config.Identities;
import de.qabel.core.config.Identity;
import de.qabel.core.config.Persistable;
import de.qabel.core.crypto.CryptoUtils;
import de.qabel.core.drop.DropMessage;
import de.qabel.core.exceptions.QblInvalidEncryptionKeyException;
import de.qabel.qabelbox.config.AndroidPersistence;
import de.qabel.qabelbox.config.QblSQLiteParams;

public class LocalQabelService extends Service {

	private static final String TAG = "LocalQabelService";
	private static final String PREF_LAST_ACTIVE_IDENTITY = "PREF_LAST_ACTIVE_IDENTITY";
	// Hardcoded password until the password is saved in the Android KeyStore
	protected static final char[] PASSWORD = "constantpassword".toCharArray();
	public static final String DEFAULT_DROP_SERVER = "http://localhost";

	private static final String PREF_DEVICE_ID_CREATED = "PREF_DEVICE_ID_CREATED";
	private static final String PREF_DEVICE_ID = "PREF_DEVICE_ID";
	private static final int NUM_BYTES_DEVICE_ID = 16;
	public static final String ALIAS_PREFERENCES_CERT = "databasePassword";
	public static final String PREF_DATABASE_PASSWORD = "DATABASE_PASSWORD";

	private final IBinder mBinder = new LocalBinder();

	protected static final String DB_NAME = "qabel-service";
	protected static final int DB_VERSION = 1;
	protected AndroidPersistence persistence;
	SharedPreferences sharedPreferences;
	KeyStore keyStore;
	private CryptoUtils cryptoUtils;

	protected void setLastActiveIdentityID(String identityID) {
		sharedPreferences.edit()
				.putString(PREF_LAST_ACTIVE_IDENTITY, identityID)
				.apply();
	}

	protected String getLastActiveIdentityID() {
		return sharedPreferences.getString(PREF_LAST_ACTIVE_IDENTITY, "");
	}

	public void addIdentity(Identity identity) {
		persistence.updateOrPersistEntity(identity);
	}

	public Identities getIdentities() {
		List<Persistable> entities = persistence.getEntities(Identity.class);
		Identities identities = new Identities();
		for (Persistable p : entities) {
			identities.put((Identity) p);
		}
		return identities;
	}

	public Identity getActiveIdentity() {
		String identityID = getLastActiveIdentityID();
		return getIdentities().getByKeyIdentifier(identityID);
	}

	public void setActiveIdentity(Identity identity) {
		setLastActiveIdentityID(identity.getKeyIdentifier());
	}

	public void deleteIdentity(Identity identity) {
		persistence.removeEntity(identity.getPersistenceID(), Identity.class);
	}

	/**
	 * Modify the identity in place
	 * @param identity known identity with modifid data
	 */
	public void modifyIdentity(Identity identity) {
		persistence.updateEntity(identity);
	}

	/**
	 * Create a list of all contacts that are known, regardless of the identity that owns it
	 * @return List of all contacts
	 */
	public Contacts getContacts() {
		List<Persistable> entities = persistence.getEntities(Contact.class);
		Contacts contacts = new Contacts();
		for (Persistable p : entities) {
			contacts.put((Contact) p);
		}
		return contacts;
	}

	/**
	 * Create a list of contacts for the given Identity
	 * @param identity selected identity
	 * @return List of contacts owned by the identity
	 */
	public Contacts getContacts(Identity identity) {
		List<Persistable> entities = persistence.getEntities(Contact.class);
		Contacts contacts = new Contacts();
		for (Persistable p : entities) {
			Contact c = (Contact) p;
			if (c.getContactOwner().equals(identity)) {
				contacts.put(c);
			}
		}
		return contacts;
	}

	public void addContact(Contact contact) {
		persistence.persistEntity(contact);
	}

	public void deleteContact(Contact contact) {
		persistence.removeEntity(contact.getPersistenceID(), Contact.class);
	}

	public void modifyContact(Contact contact) {
		persistence.updateEntity(contact);
	}

	/**
	 * Create a map that maps each known identity to all of its contacts
	 * @return Map of each identity to its contacts
	 */
	public Map<Identity, Contacts> getAllContacts() {
		Map<Identity, Contacts> contacts = new HashMap<>();
		List<Persistable> entities = persistence.getEntities(Contact.class);
		for (Persistable p : entities) {
			Contact c = (Contact) p;
			Identity owner = c.getContactOwner();
			Contacts map;
			if (contacts.containsKey(owner)) {
				map = contacts.get(owner);
			} else {
				map = new Contacts();
				contacts.put(owner, map);
			}
			map.put(c);
		}
		return contacts;
	}

	public void sendDropMessage(DropMessage dropMessage, Contact recipient) {

	}


	public class LocalBinder extends Binder {
		public LocalQabelService getService() {
			// Return this instance of LocalQabelService so clients can call public methods
			return LocalQabelService.this;
		}
	}

	public byte[] getDeviceID() {
		String deviceID = sharedPreferences.getString(PREF_DEVICE_ID, "");
		if (deviceID.equals("")) {
			// Should never occur
			throw new RuntimeException("DeviceID not created!");
		}
		return Hex.decode(deviceID);
	}

	@Override
	public IBinder onBind(Intent intent) {
		return mBinder;
	}

	@Override
	public void onCreate() {
		super.onCreate();
		Log.i(TAG, "LocalQabelService created");
		initSharedPreferences();
		cryptoUtils = new CryptoUtils();
		char[] password;
		password = retrieveDatabasePassword();
		if (password == null) {
			Log.e(TAG, "KeyStore init failed");
			return;
		}
		QblSQLiteParams params = new QblSQLiteParams(this, DB_NAME, null, DB_VERSION);
		initDatabase(params, password);
	}

	private char[] retrieveDatabasePassword() {
		KeyPair keyPair = retrieveKeyPair();
		if (keyPair == null) {
			return null;
		}
		String encryptedDBPassword = null;
		if (sharedPreferences.contains(PREF_DATABASE_PASSWORD)) {
			encryptedDBPassword = sharedPreferences.getString(PREF_DATABASE_PASSWORD, null);
		}
		char[] password;
		if (encryptedDBPassword == null) {
			try {
				password = createDBPassword(keyPair);
			} catch (IOException e) {
				return null;
			}
		} else {
			password = decryptDBPassword(keyPair);
		}
		return password;
	}

	private char[] decryptDBPassword(KeyPair keyPair) {
		return new char[0];
	}

	private char[] createDBPassword(KeyPair keyPair) throws IOException {
		String password = RandomStringUtils.random(30);
		sharedPreferences.edit().putString(PREF_DATABASE_PASSWORD, "foobar")
				.apply();
		Cipher input;
		try {
			input = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
			input.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			Log.e(TAG, "Cypher not available", e);
			return null;
		} catch (InvalidKeyException e) {
			Log.e(TAG, "Could not decrypt db key");
			return null;
		}
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		CipherOutputStream cipherOutputStream = new CipherOutputStream(
				outputStream, input);
		cipherOutputStream.write(password.getBytes("UTF-8"));
		cipherOutputStream.close();

		byte [] encrypted = outputStream.toByteArray();
		return Base64.encodeToString(encrypted, Base64.DEFAULT).toCharArray();
	}

	private KeyPair retrieveKeyPair() {
		KeyPair keyPair = null;
		try {
			keyStore = KeyStore.getInstance("AndroidKeyStore");
			keyStore.load(null);
			// API Level 23 changed the whole KeyStore API.
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
				keyStoreParameter = new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
						.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
						.build();
			} else {
				// deprecated since API level 23
				// https://developer.android.com/reference/android/security/KeyStoreParameter.Builder.html
				keyStoreParameter = new KeyStoreParameter.Builder(getApplicationContext())
						.setEncryptionRequired(false)
						.build();
				if (keyStore.containsAlias(ALIAS_PREFERENCES_CERT)) {
					KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS_PREFERENCES_CERT, null);
					RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();
					RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
					keyPair = new KeyPair(publicKey, privateKey);
				} else {
					keyPair = generateKeyPair();
				}
			}
		} catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException |
				InvalidAlgorithmParameterException | UnrecoverableEntryException | NoSuchProviderException e) {
			Log.e(TAG, "Could not retrieve key pair from KeyStore", e);
		}
		return keyPair;
	}

	private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		Calendar start = Calendar.getInstance();
		Calendar end = Calendar.getInstance();
		// 100 year certificate should be enough.
		end.add(Calendar.YEAR, 100);
		KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(getApplicationContext())
				.setAlias(ALIAS_PREFERENCES_CERT)
				.setSubject(new X500Principal("CN=Qabel, O=Android Authority"))
				.setSerialNumber(BigInteger.ONE)
				.setStartDate(start.getTime())
				.setEndDate(end.getTime())
				.build();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
		generator.initialize(spec);

		return generator.generateKeyPair();
	}

	@Nullable
	private AndroidPersistence initDatabase(QblSQLiteParams params, char[] password) {
		try {
			return new AndroidPersistence(params, password);
		} catch (QblInvalidEncryptionKeyException e) {
			Log.e(TAG, "Invalid database password, resetting DB!");
			getApplicationContext().deleteDatabase(DB_NAME);
			try {
				return new AndroidPersistence(params, password);
			} catch (QblInvalidEncryptionKeyException e1) {
				Log.e(TAG, "Could not recreate database");
				return null;
			}
		}
	}

	protected void initSharedPreferences() {
		sharedPreferences = getSharedPreferences(this.getClass().getCanonicalName(), MODE_PRIVATE);
		if (!sharedPreferences.getBoolean(PREF_DEVICE_ID_CREATED, false)) {

			byte[] deviceID = cryptoUtils.getRandomBytes(NUM_BYTES_DEVICE_ID);

			Log.d(this.getClass().getName(), "New device ID: " + Hex.toHexString(deviceID));

			sharedPreferences.edit().putString(PREF_DEVICE_ID, Hex.toHexString(deviceID))
					.putBoolean(PREF_DEVICE_ID_CREATED, true)
					.apply();
		}
	}

	@Override
	public void onDestroy() {
		super.onDestroy();
	}

}

