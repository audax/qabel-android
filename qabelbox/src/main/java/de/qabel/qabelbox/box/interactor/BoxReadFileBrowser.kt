package de.qabel.qabelbox.box.interactor

import de.qabel.box.storage.BoxNavigation
import de.qabel.box.storage.BoxObject
import de.qabel.box.storage.dto.BoxPath
import de.qabel.box.storage.exceptions.QblStorageException
import de.qabel.core.config.Identity
import de.qabel.core.logging.QabelLog
import de.qabel.core.repository.ContactRepository
import de.qabel.core.repository.exception.EntityNotFoundException
import de.qabel.qabelbox.box.BoxScheduler
import de.qabel.qabelbox.box.dto.BrowserEntry
import de.qabel.qabelbox.box.provider.DocumentId
import de.qabel.qabelbox.box.toEntry
import rx.Observable
import rx.lang.kotlin.observable
import rx.lang.kotlin.toSingletonObservable
import java.io.FileNotFoundException
import javax.inject.Inject

open class BoxReadFileBrowser @Inject constructor(protected val keyAndPrefix: KeyAndPrefix,
                                                  val volumeNavigator: VolumeNavigator,
                                                  private val contactRepo: ContactRepository,
                                                  protected val scheduler: BoxScheduler
) : ReadFileBrowser, QabelLog {

    data class KeyAndPrefix(val publicKey: String, val prefix: String) {
        constructor(identity: Identity) : this(identity.keyIdentifier, identity.prefixes.first().prefix)
    }

    override fun asDocumentId(path: BoxPath) = DocumentId(keyAndPrefix.publicKey, keyAndPrefix.prefix, path).toSingletonObservable()

    override fun query(path: BoxPath): Observable<BrowserEntry> = observable<BrowserEntry> {
        subscriber ->
        if (path is BoxPath.Root) {
            subscriber.onNext(BrowserEntry.Folder(""))
            return@observable
        }
        val (boxObject, navigation) = try {
            volumeNavigator.queryObjectAndNav(path)
        } catch (e: Throwable) {
            subscriber.onError(e)
            return@observable
        }
        val entry = toEntry(boxObject, navigation)
        if (entry == null) {
            subscriber.onError(FileNotFoundException("File or Folder ${path.name} not found"))
            return@observable
        }

        subscriber.onNext(entry)
    }.subscribeOn(scheduler.rxScheduler)

    private fun toEntry(boxObject: BoxObject, navigation: BoxNavigation): BrowserEntry? {
        val entry = boxObject.toEntry()
        entry?.let {
            val shares = navigation.getSharesOf(boxObject)
            shares.forEach {
                try {
                    entry.sharedTo.add(contactRepo.findByKeyId(it.recipient))
                } catch (ex: EntityNotFoundException) {
                    entry.sharedTo.add(null)
                }
            }
        }
        return entry
    }

    override fun list(path: BoxPath.FolderLike): Observable<List<BrowserEntry>> =
            observable<List<BrowserEntry>> {
                subscriber ->
                val nav = try {
                    volumeNavigator.navigateTo(path).apply { refresh() }
                } catch (e: QblStorageException) {
                    subscriber.onError(e)
                    return@observable
                }
                val entries = nav.listFolders().sortedBy { it.name } + nav.listFiles().sortedBy { it.name }
                subscriber.onNext(entries.map { toEntry(it, nav) }.filterNotNull())
            }.subscribeOn(scheduler.rxScheduler)

}
