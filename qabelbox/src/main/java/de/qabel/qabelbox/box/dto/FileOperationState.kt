package de.qabel.qabelbox.box.dto

import de.qabel.box.storage.dto.BoxPath
import de.qabel.qabelbox.box.dto.FileOperationState.Status
import de.qabel.qabelbox.box.interactor.BoxReadFileBrowser

data class FileOperationState(val ownerKey: BoxReadFileBrowser.KeyAndPrefix,
                              val entryName: String, val path: BoxPath.FolderLike,
                              val time: Long = System.currentTimeMillis(),
                              var done: Long = 0, var size: Long = 0,
                              var status: Status = Status.PREPARE) {

    enum class Status {
        PREPARE, LOADING, COMPLETING, COMPLETE, ERROR, CANCELED
    }

    val loadDone: Boolean
        get() = (done == size)

}
