package de.qabel.qabelbox.services;

import android.content.Intent;
import android.test.ServiceTestCase;

import org.apache.http.protocol.HTTP;

import java.net.URI;
import java.net.URL;
import java.util.Map;

import de.qabel.core.config.Contact;
import de.qabel.core.config.Contacts;
import de.qabel.core.config.Identities;
import de.qabel.core.config.Identity;
import de.qabel.core.crypto.QblECKeyPair;
import de.qabel.core.drop.DropMessage;
import de.qabel.core.exceptions.QblDropPayloadSizeException;
import de.qabel.core.http.DropHTTP;
import de.qabel.core.http.HTTPResult;

import static org.mockito.Mockito.*;

public class LocalQabelServiceTest extends ServiceTestCase<LocalQabelService> {

	private LocalQabelService mService;
	private Identity identity;
	private Contact contact;

	public LocalQabelServiceTest() {
		super(LocalQabelService.class);
	}

	@Override
	protected void setUp() throws Exception {
		super.setUp();
		getContext().deleteDatabase(LocalQabelService.DB_NAME);
		Intent intent = new Intent(getContext(), LocalQabelService.class);
		startService(intent);
		this.mService = getService();
		identity = new Identity("foo", null, new QblECKeyPair());
		mService.addIdentity(identity);
		mService.setActiveIdentity(identity);

		contact = new Contact(identity, "foo", null, new QblECKeyPair().getPub());
	}

	public void testRetrieveIdentity() {
		Identities identities = mService.getIdentities();
		assertTrue(identities.getIdentities().contains(identity));
	}

	public void testGetActiveIdentity() {
		assertEquals(identity, mService.getActiveIdentity());
	}

	public void testDeleteIdentity() {
		mService.deleteIdentity(identity);
		Identities identities = mService.getIdentities();
		assertFalse(identities.getIdentities().contains(identity));
		assertNull(mService.getActiveIdentity());
	}

	public void testModifyIdentity() {
	    identity.setAlias("bar");
		mService.modifyIdentity(identity);
		assertEquals(identity.getAlias(), mService.getActiveIdentity().getAlias());
	}

	public void testAddContact() {
		mService.addContact(contact);
		assertTrue(mService.getContacts(identity).getContacts().contains(contact));
	}

	public void testDeleteContact() {
		mService.addContact(contact);
		assertTrue(mService.getContacts(identity).getContacts().contains(contact));
		mService.deleteContact(contact);
		assertFalse(mService.getContacts(identity).getContacts().contains(contact));
	}

	public void testModifyContact() {
		mService.addContact(contact);
		contact.setAlias("bar");
		mService.modifyContact(contact);
		assertTrue(mService.getContacts(identity).getContacts().contains(contact));
		contact.setAlias("foo");
		assertFalse(mService.getContacts(identity).getContacts().contains(contact));
	}

	public void testGetAllContacts() {
		mService.addContact(contact);
		Identity secondIdentity = new Identity("bar", null, new QblECKeyPair());
		mService.addIdentity(identity);
		Contact secondContact = new Contact(secondIdentity, "blub", null, new QblECKeyPair().getPub());
		mService.addContact(secondContact);
		Map<Identity, Contacts> contacts = mService.getAllContacts();
		assertEquals(2, contacts.size());
		assertTrue(contacts.containsKey(identity));
		assertTrue(contacts.containsKey(secondIdentity));
		assertTrue(contacts.get(identity).getContacts().contains(contact));
		assertTrue(contacts.get(secondIdentity).getContacts().contains(secondContact));
	}

	public void testSendDropMessage() throws QblDropPayloadSizeException {
		DropHTTP dropMock = mock(DropHTTP.class);
		DropMessage dropMessage = new DropMessage(identity, "foo", "TEST");
		HTTPResult httpMock = mock(HTTPResult.class);
		when(httpMock.getResponseCode()).thenReturn(200);
		when(dropMock.send((URI) any(), (byte[]) any())).thenReturn(httpMock);

		mService.sendDropMessage(dropMessage, contact);

		verify(dropMock).send(eq(contact.getDropUrls().iterator().next().getUri()),
				any(byte[].class));
	}

}
