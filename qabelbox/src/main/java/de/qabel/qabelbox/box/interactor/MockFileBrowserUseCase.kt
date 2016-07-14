package de.qabel.qabelbox.box.interactor

import de.qabel.qabelbox.box.dto.*
import de.qabel.qabelbox.box.toDownloadSource
import rx.Observable
import rx.lang.kotlin.toSingletonObservable
import java.io.ByteArrayInputStream
import java.util.*
import javax.inject.Inject

class MockFileBrowserUseCase @Inject constructor(): FileBrowserUseCase {
    override fun createFolder(path: BoxPath.Folder): Observable<Unit> {
        storage += Pair(path, null)
        return Unit.toSingletonObservable()
    }

    val storage = mutableListOf<Pair<BoxPath, ByteArray?>>()

    override fun download(path: BoxPath.File): Observable<DownloadSource> {
        for ((filepath, content) in storage) {
            if (filepath == path) {
                content ?: throw IllegalArgumentException("Not a file")
                return content.toDownloadSource().toSingletonObservable()
            }
        }
        return Observable.error<DownloadSource>(IllegalArgumentException("File not found"))
    }

    override fun delete(path: BoxPath): Observable<Unit> {
        if (path is BoxPath.File) {
            storage.forEachIndexed { i, pair ->
                if (path == pair.first) {
                    storage.removeAt(i)
                }
            }
        } else if (path is BoxPath.Folder) {
            TODO()
        }
        return Unit.toSingletonObservable()
    }

    override fun list(path: BoxPath.FolderLike): Observable<List<BrowserEntry>> {
        return storage.filter { it.first.parent == path }.map { pair ->
            val (filepath, content) = pair
            when (filepath) {
                is BoxPath.File -> {
                    content ?: throw IllegalArgumentException("No content")
                    BrowserEntry.File(filepath.name, content.size.toLong(), Date())
                }
                is BoxPath.FolderLike -> BrowserEntry.Folder(filepath.name)
            }
        }.toSingletonObservable()
    }

    override fun upload(path: BoxPath.File, source: UploadSource): Observable<Unit> {
        storage += Pair(path, source.source.readBytes())
        return Unit.toSingletonObservable()
    }
}

