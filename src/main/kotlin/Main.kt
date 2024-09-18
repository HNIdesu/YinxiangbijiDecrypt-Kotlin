import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import org.apache.commons.cli.DefaultParser
import org.apache.commons.cli.HelpFormatter
import org.apache.commons.cli.Options
import org.apache.commons.cli.ParseException
import org.w3c.dom.Document
import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.zip.DataFormatException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import kotlin.experimental.xor
import kotlin.io.path.Path
import kotlin.io.path.absolute

val HMACKEY="{22C58AC3-F1C7-4D96-8B88-5E4BBF505817}".encodeToByteArray()
fun replaceFileExtension(filePath: String, newExtension: String): String {
    val file = File(filePath)
    val newFileName = file.nameWithoutExtension + newExtension
    return File(file.parent, newFileName).absolutePath
}

fun hmacSha256Digest(key:ByteArray,data:ByteArray,offset:Int,length:Int):ByteArray{
    val keySpec=SecretKeySpec(key,"HmacSHA256")
    val mac=Mac.getInstance("HmacSHA256")
    mac.init(keySpec)
    mac.update(data,offset,length)
    return mac.doFinal()
}

fun aesCbcDecrypt(key:ByteArray,data:ByteArray,iv:ByteArray):ByteArray{
    val cipher=Cipher.getInstance("AES/CBC/PKCS5Padding")
    val ivSpec=IvParameterSpec(iv)
    val keySpec=SecretKeySpec(key,"AES")
    cipher.init(Cipher.DECRYPT_MODE,keySpec,ivSpec)
    return cipher.doFinal(data)
}

fun generateKey(nonce:ByteArray,result :ByteArray):ByteArray{
    var tmp=nonce
    for(i in 0 until 50000)
    {
        tmp=hmacSha256Digest(HMACKEY,tmp,0,tmp.size)
        for(j in 0 until 16)
            result[j]=result[j].xor(tmp[j])
    }
    return result
}


class DecryptResult(val contentElement:Element, val content:String)
suspend fun decryptNote(input:String):String{
    val encryptedData=Base64.getMimeDecoder().decode(input)
    return ByteArrayInputStream(encryptedData).use { s1 ->
        val signature = ByteArray(4)
        s1.read(signature)
        if (signature.toString(StandardCharsets.UTF_8) != "ENC0")
            throw DataFormatException("File signature verification failed")
        val nonce1 = ByteArray(20)
        s1.read(nonce1, 0, 16)
        nonce1[19] = 1
        val nonce2 = ByteArray(20)
        s1.read(nonce2, 0, 16)
        nonce2[19] = 1
        val iv = ByteArray(16)
        s1.read(iv)
        val key1=ByteArray(16)
        val key2=ByteArray(16)
        coroutineScope {
            launch {
                generateKey(nonce1,key1)
            }
            launch {
                generateKey(nonce2,key2)
            }
        }
        val dataLength = encryptedData.size - 16 * 5 - 4
        val data = ByteArray(dataLength)
        coroutineScope {
            launch {
                s1.read(data)
                val hash = ByteArray(32)
                s1.read(hash)
                if(!hmacSha256Digest(key2,encryptedData,0,encryptedData.size-32).contentEquals(hash))
                    throw Exception("Hash verification failed")
            }
        }
        coroutineScope {
            val decryptedData = aesCbcDecrypt(key1, data, iv)
            String(decryptedData,0,decryptedData.size - 1, StandardCharsets.UTF_8)
        }
    }
}

fun decryptNotes(dom:Document):Flow<DecryptResult>{
    return channelFlow {
        val noteElementList=dom.documentElement.getElementsByTagName("note")
        coroutineScope {
            repeat(noteElementList.length){i->
                val noteElement=noteElementList.item(i) as Element
                val contentElement=noteElement.getElementsByTagName("content").item(0) as Element
                if(contentElement.getAttribute("encoding")=="base64:aes"){
                    launch(Dispatchers.Default) {
                        println("Decrypting note:${noteElement.getElementsByTagName("title").item(0).textContent}")
                        val result=decryptNote(contentElement.textContent)
                        send(DecryptResult(contentElement,result))
                    }
                }
            }
        }
    }
}


fun decryptFile(srcPath:String,savePath:String){
    println("Decrypting file:$srcPath")
    val startTime=System.currentTimeMillis()
    val dom=DocumentBuilderFactory.newInstance().apply {
        setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
        isValidating = false
        setFeature("http://xml.org/sax/features/external-general-entities", false)
        setFeature("http://xml.org/sax/features/external-parameter-entities", false)

    }.newDocumentBuilder().parse(File(srcPath))
    var decryptedCount=0;
    runBlocking {
        decryptNotes(dom).collect{
            it.contentElement.removeAttribute("encoding")
            it.contentElement.firstChild.textContent=it.content
            decryptedCount++
        }
    }
    val endTime=System.currentTimeMillis()
    println("Decryption completed,$decryptedCount notes decrypted")
    println("${"%.2f".format((endTime-startTime)/1000.0)}s elapsed")
    val transformer=TransformerFactory.newInstance().newTransformer()
    transformer.transform(DOMSource(dom),StreamResult(FileOutputStream(savePath)))
    println("File has been saved to ${File(savePath).absolutePath}")
}

fun main(args:Array<String>){
    val parser=DefaultParser()
    val options=Options()
    options.addRequiredOption("i","path",true,"Path or directory to the .notes file(s).")
    options.addOption("o","output_directory",true,"The directory to save the decrypted file(s).")
    try{
        val commandLine=parser.parse(options,args)
        val file= File(commandLine.getOptionValue("i"))
        val outputDirectory=File(commandLine.getOptionValue("o","."))
        if(!file.exists()){
            println("Path ${file.absolutePath} not exists")
            return
            
        }
        if(!outputDirectory.exists())
            outputDirectory.mkdirs()
        if(file.isDirectory){
            for (file1 in file.walk(FileWalkDirection.TOP_DOWN)) {
                val path1=file1.path
                if(path1.endsWith(".notes"))
                    decryptFile(path1, replaceFileExtension(path1,".enex"))
            }
        }else
            decryptFile(file.path,replaceFileExtension(file.path,".enex"))

    }catch (ex:ParseException){
        HelpFormatter().printHelp("yinxiangbijidecrypt",options)
    }
}