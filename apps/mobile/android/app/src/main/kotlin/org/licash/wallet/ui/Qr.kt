package org.licash.wallet.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** `text` as a QR code, one pixel a module: drawn scaled, unfiltered. */
fun qrBitmap(text: String): ImageBitmap {
    val hints = mapOf(
        EncodeHintType.MARGIN to 0,
        // Upper case codes take the alphanumeric mode where they can.
        EncodeHintType.QR_COMPACT to true,
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
    )
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints)
    val (w, h) = matrix.width to matrix.height
    val pixels = IntArray(w * h) { if (matrix[it % w, it / w]) 0xFF000000.toInt() else -1 }
    return Bitmap.createBitmap(pixels, w, h, Bitmap.Config.ARGB_8888).asImageBitmap()
}

/** A QR code on white, as scanners read best: `description` says what it is. */
@Composable
fun QrCode(text: String, size: Dp = 280.dp, description: String = "QR code") {
    val bitmap = remember(text) { qrBitmap(text) }
    Box(
        Modifier.clip(RoundedCornerShape(24.dp)).background(Color.White).padding(18.dp),
    ) {
        Image(
            bitmap,
            contentDescription = description,
            modifier = Modifier.widthIn(max = size).aspectRatio(1f),
            filterQuality = FilterQuality.None,
        )
    }
}
