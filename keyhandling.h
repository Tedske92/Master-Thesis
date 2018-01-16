#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <mxml.h>

//gcc testenv.c -I/usr/include/openssl -lcurl -lmxml -lcrypto -o testenv
 
#define KEY_LENGTH  2048
#define PUB_EXP     3
//enc/dec
//sign
//veri
struct rsaKEYS {    
 char *privateK;
 char *publicK;
};

struct aesKEYS {
 unsigned char *symmK;
 unsigned char *IV;
};

struct cryptoKEYS {    
	unsigned char *privateK;
	unsigned char *publicK;
	unsigned char *symmK;
	unsigned char *IV;
};


struct aesKEYS genAES(){

    char databuffer[16];
    char saltbuffer[8];
    int written;
    const EVP_CIPHER *cipher;
  
    const EVP_MD *dgst = NULL;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    written = RAND_bytes(databuffer, sizeof(databuffer));
    RAND_seed(databuffer, written);
    const char *password = databuffer;
    RAND_bytes(saltbuffer, sizeof(saltbuffer));
    const unsigned char *salt = saltbuffer;
    int i;
	struct aesKEYS aeskeys;
	aeskeys.symmK = (char *)malloc(32);
	aeskeys.IV = (char *)malloc(16);

    OpenSSL_add_all_algorithms();

    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if(!cipher) { fprintf(stderr, "no such cipher\n"); return aeskeys; }

    dgst = EVP_get_digestbyname("sha256");
    if(!dgst) { fprintf(stderr, "no such digest\n"); return aeskeys; }

    if(!EVP_BytesToKey(cipher, dgst, salt,
        (unsigned char *) password,
        strlen(password), 10, key, iv))
    {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return aeskeys;
    }

	//memcpy(aeskeys.symmK, key, sizeof(key));
	//memcpy(aeskeys.IV, iv, sizeof(iv));
	
    return aeskeys;

}

struct rsaKEYS genRSA(){
	
	struct rsaKEYS keys;
   	size_t pri_len;            // Length of private key
    	size_t pub_len;            // Length of public key
	char *pri_key;
	char *pub_key;

	RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);;
	BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char*)malloc(pri_len + 1);
    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

	keys.publicK = pub_key;
	keys.privateK = pri_key;

	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);
	
	return keys;
}

char *random64(){
	unsigned char databuffer[18];
	unsigned char *encodedData = (char *) malloc(50);
	do{
	RAND_bytes(databuffer, sizeof(databuffer));
	EVP_EncodeBlock(encodedData, databuffer, 18);
	}while(getfilePath(strcat(encodedData,".bin"))!=NULL || (strstr(encodedData,"/") != NULL) || (strstr(encodedData,"+") != NULL));

	return encodedData;
}

int initkeyring(const char *file){
	FILE *fp;
	fp = fopen(file,"w");
	fprintf(fp,"<?xml version=\"1.0\" encoding=\"utf-8\"?><keyring> </keyring>");
	fclose(fp);
}



int keyrename(const char *keyfile, const char *path, const char *newpath){
	
	FILE *fp;
    	mxml_node_t *tree;  
    	mxml_node_t *keyring;  
   	mxml_node_t *file; 

	fp = fopen(keyfile, "r");
   	tree = mxmlLoadFile(NULL, fp,MXML_NO_CALLBACK);
	fclose(fp);
	
	file = mxmlFindElement(tree, tree, "file",
                           "path", path,
                           MXML_DESCEND);

	mxmlElementSetAttrf(file,"path","%s",newpath);

	fp = fopen(keyfile, "w");
	mxmlSaveFile(tree, fp, MXML_NO_CALLBACK);
	fclose(fp);
}

struct cryptoKEYS readKeys(const char *keyfile, const char *path){
	FILE *fp;
	mxml_node_t *tree;  
    mxml_node_t *file; 
    mxml_node_t *data;
	struct cryptoKEYS keys;
	
	fp = fopen(keyfile, "r");
   	tree = mxmlLoadFile(NULL, fp,MXML_NO_CALLBACK);
	fclose(fp);
	//check if path already exists
	//if its null it means mknod was called by write
	file = mxmlFindElement(tree, tree, NULL,
                           "path", path,
                           MXML_DESCEND);

	data = mxmlFindElement(file, tree, "data",
                           NULL, NULL,
                           MXML_DESCEND);

	keys.publicK = (char *)mxmlElementGetAttr(data, "pubkey");
	keys.privateK = (char *)mxmlElementGetAttr(data, "prikey");
	keys.symmK = (char *)mxmlElementGetAttr(data, "symmkey");
	keys.IV = (char *)mxmlElementGetAttr(data, "iv");

	return keys;
}
//keygen/sym/asym
int writeKeys(const char *keyfile, const char *localpath){

    FILE *fp;
    mxml_node_t *tree;  
    mxml_node_t *keyring;  
    mxml_node_t *file;  
    mxml_node_t *data; 
    mxml_node_t *node;
	
	char *pub_key;
	char *pri_key;
	
	fp = fopen(keyfile, "r");
   	tree = mxmlLoadFile(NULL, fp,MXML_NO_CALLBACK);
	fclose(fp);
	//check if path already exists
	//if its null it means mknod was called by write
	node = mxmlFindElement(tree, tree, NULL,
                           "path", localpath,
                           MXML_DESCEND);
	if(node == NULL){
	struct rsaKEYS rsakeys = genRSA();	
	struct aesKEYS aeskeys = genAES();

	keyring = mxmlFindElement(tree, tree, "keyring",
                           NULL, NULL,
                           MXML_DESCEND);

	file = mxmlNewElement(keyring, "file");
	mxmlElementSetAttrf(file,"path","%s",localpath);

	//write data to key ring, symmetric key and IV is fixed
	data = mxmlNewElement(file, "data");
 	mxmlElementSetAttr(data,"symmkey","03762ec24a14cf7513775f25b25c05186093ca68a29d026301ebaa14b9ff8ce8");
	mxmlElementSetAttrf(data,"iv","80739b43edd09ba6665002101f7453ad");       
	mxmlElementSetAttrf(data,"pubkey","%s", rsakeys.publicK);   
	mxmlElementSetAttrf(data,"prikey","%s", rsakeys.privateK);
        
	fp = fopen(keyfile, "w");
	mxmlSaveFile(tree, fp, MXML_NO_CALLBACK);
	fclose(fp);
	}

return 0;
  
}
//read serverpath, if null make new one

char *readServerName(const char *keyfile, const char *path, int flag){
	FILE *fp;
    char *serverName;
	mxml_node_t *tree;  
    	mxml_node_t *node;  
	fp = fopen(keyfile, "r");
	tree = mxmlLoadFile(NULL, fp,MXML_TEXT_CALLBACK);
	fclose(fp);
	node = mxmlFindElement(tree, tree, "file",
                           "path", path,
                           MXML_DESCEND);
	
	node = mxmlFindElement(node,tree,"data",NULL,NULL,MXML_DESCEND);
	serverName = (char *) mxmlElementGetAttr(node,"servername");
	//if flag is 0, serverName will return right away
	if(flag != 0 && serverName == NULL){
		serverName = random64();
		mxmlElementSetAttrf(node,"servername", "%s", serverName);

		fp = fopen(keyfile,"w");
		mxmlSaveFile(tree, fp, MXML_NO_CALLBACK);
		fclose(fp);
		return serverName;		
	}else{
		return serverName;
	}
	
}

void setServerPath(const char *keyfile, const char *path, char *ext){
	FILE *fp;
	char *serverPath;
    char *serverName;
	char *sname;
	mxml_node_t *tree;  
    	mxml_node_t *node;  

	fp = fopen(keyfile, "r");
	tree = mxmlLoadFile(NULL, fp,MXML_TEXT_CALLBACK);
	fclose(fp);
	node = mxmlFindElement(tree, tree, "file","path", path,MXML_DESCEND);
	node = mxmlFindElement(node,tree,"data",NULL,NULL,MXML_DESCEND);

	//find server name, and then server path
	serverName = (char *) mxmlElementGetAttr(node,"servername");
	serverPath = getfilePath(serverName);
	mxmlElementSetAttrf(node,"serverpath", "%s", serverPath);


		fp = fopen(keyfile,"w");
		mxmlSaveFile(tree, fp, MXML_NO_CALLBACK);
		fclose(fp);
}

void writeSharedKey(const char *sharepath, const char *keyring){
	FILE *fp;
	mxml_node_t *tree;
	mxml_node_t *node;
	
	mxml_node_t *xml;
	mxml_node_t *keyringnode;
	mxml_node_t *file;
	mxml_node_t *data;

	char *newsharefile = malloc(32);
	strcpy(newsharefile, sharepath);	
	
	const char *symmkey;
	const char *iv;
	const char *pubkey;
	const char *privkey;
	const char *servername;
	const char *serverpath;

	fp = fopen(keyring, "r");
	tree = mxmlLoadFile(NULL, fp,MXML_TEXT_CALLBACK);
	fclose(fp);

	xml = mxmlNewXML("1.0");
	keyringnode = mxmlNewElement(xml,"keyring");
	file = mxmlNewElement(keyringnode, "file");
	//read information from key ring, and write to new information file	
		
		node = mxmlFindElement(tree, tree, "file",
                           "path", sharepath,
                           MXML_DESCEND);

		node = mxmlFindElement(node,tree,"data",NULL,NULL,MXML_DESCEND);
		
		mxmlElementSetAttrf(file,"path", "%s", basename((char *)sharepath));

		data = mxmlNewElement(file, "data");
		
		
		symmkey = mxmlElementGetAttr(node, "symmkey");
		mxmlElementSetAttrf(data, "symmkey", "%s", symmkey);
	
		iv = mxmlElementGetAttr(node, "iv");
		mxmlElementSetAttrf(data, "iv", "%s", iv);

		pubkey = mxmlElementGetAttr(node, "pubkey");
		mxmlElementSetAttrf(data, "pubkey", "%s", pubkey);

		mxmlElementSetAttr(data, "prikey", "");
			

		servername = mxmlElementGetAttr(node, "servername");
		mxmlElementSetAttrf(data, "servername", "%s", servername);
	

		serverpath = mxmlElementGetAttr(node, "serverpath");
		mxmlElementSetAttrf(data, "serverpath", "%s", serverpath);

		

	fp = fopen(strcat(newsharefile,".share"), "w");
	mxmlSaveFile(xml, fp, MXML_NO_CALLBACK);
	fclose(fp);
}

int writeInitKeys(const char *keyfile, const char *localpath, const char *symmkey, const char *iv, const char * pubkey, const char *prikey, const char *servername, const char *serverpath){

//int *inode, char *path, unsigned char key[], unsigned char iv[]
    FILE *fp;
    mxml_node_t *tree;  
    mxml_node_t *keyring;  
    mxml_node_t *file;  
    mxml_node_t *data; 
    mxml_node_t *node;
	
	fp = fopen(keyfile, "r");
   	tree = mxmlLoadFile(NULL, fp,MXML_NO_CALLBACK);
	fclose(fp);
	//check if path already exists
	//if its null it means mknod was called by write
	node = mxmlFindElement(tree, tree, NULL,
                           "path", localpath,
                           MXML_DESCEND);
	if(node == NULL){
	
	keyring = mxmlFindElement(tree, tree, "keyring",
                           NULL, NULL,
                           MXML_DESCEND);

	file = mxmlNewElement(keyring, "file");
	mxmlElementSetAttrf(file,"path","%s",localpath);

	//write new filee to key ring
	data = mxmlNewElement(file, "data");
 	mxmlElementSetAttrf(data,"symmkey","%s",symmkey);
	mxmlElementSetAttrf(data,"iv","%s",iv);       
	mxmlElementSetAttrf(data,"pubkey","%s",pubkey);   
	mxmlElementSetAttrf(data,"prikey","%s",prikey);
	mxmlElementSetAttrf(data,"servername","%s",servername);
	mxmlElementSetAttrf(data,"serverpath","%s",serverpath);
        
	fp = fopen(keyfile, "w");
	mxmlSaveFile(tree, fp, MXML_NO_CALLBACK);
	fclose(fp);
	}

return 0;
  
}

int fileInKeyRing(const char *keyfile, const char *serverpath){
	FILE *fp;
	mxml_node_t *tree;  
  	mxml_node_t *node;
	mxml_node_t *data;
	

	fp = fopen(keyfile, "r");
	tree = mxmlLoadFile(NULL, fp,MXML_TEXT_CALLBACK);
	fclose(fp);

for (node = mxmlFindElement(tree, tree,
                                "file",
                                NULL, NULL,
                                MXML_DESCEND);
         node != NULL;
         node = mxmlFindElement(node, tree,
                                "file",
                                NULL, NULL,
                                MXML_DESCEND))
	{
		//check if file exists in key ring
		data = mxmlFindElement(node,tree,"data","serverpath",serverpath,MXML_DESCEND);
		if(data != NULL)
			return 1;
	}
	return 0;
}

void initFileSystem(const char *masterkey, const char *keyfile, const char *root){
	FILE *fp;
	mxml_node_t *tree;  
  	mxml_node_t *node; 

	const char *localpath;
	const char *symmk;
	const char *iv;
	const char *pubk;
	const char *prik;
	const char *servername;
	const char *serverpath;
 
	fp = fopen(keyfile, "r");
	tree = mxmlLoadFile(NULL, fp,MXML_TEXT_CALLBACK);
	fclose(fp);
for (node = mxmlFindElement(tree, tree,
                                "file",
                                NULL, NULL,
                                MXML_DESCEND);
         node != NULL;
         node = mxmlFindElement(node, tree,
                                "file",
                                NULL, NULL,
                                MXML_DESCEND))
    {	
		char *rootdir = malloc(128);
		strcpy(rootdir,root);
		strcat(rootdir, "/");
		localpath = mxmlElementGetAttr(node, "path");
		node = mxmlFindElement(node,tree,"data",NULL,NULL,MXML_DESCEND);
		
		symmk = mxmlElementGetAttr(node, "symmkey");
		iv = mxmlElementGetAttr(node, "iv");
		pubk = mxmlElementGetAttr(node, "pubkey");
		prik = mxmlElementGetAttr(node, "prikey");
		servername = mxmlElementGetAttr(node, "servername");
		serverpath = mxmlElementGetAttr(node, "serverpath");
		
		download("/tmp/cryptfile.bin", serverpath);
		//check if the file is already a part of the file system and decrypt it
		if((strstr(localpath,rootdir) != NULL)){
			decryptFile(localpath,symmk,iv);
			writeInitKeys(masterkey, localpath, symmk, iv, pubk, prik, servername, serverpath);
			
		}else if(fileInKeyRing(masterkey,serverpath) == 0){
			//then local path is only a name and file is in a shared key ring
			decryptFile(strcat(rootdir, localpath),symmk,iv);
			writeInitKeys(masterkey, rootdir, symmk, iv, pubk, prik, servername, serverpath);
		}
		
		if(strstr(localpath,"_SHAREKEY.xml") != NULL){
			//the file is a shared key ring
			decryptFile(strcat(rootdir, localpath),symmk,iv);
			initFileSystem(masterkey, rootdir, root);
		}
			
    }
}
