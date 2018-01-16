#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h> 
#include <mxml.h>
#include "crypto.h"
#include "client_server.h"
#include "keyhandling.h"
void shareKeyFile(char *keyfile, char *loadfile, char *filerights[], int arrlen){
clock_t start = clock();
	FILE *fp;
	mxml_node_t *tree;  
  	mxml_node_t *node;

	mxml_node_t *xml;
	mxml_node_t *keyring;
	mxml_node_t *file;
	mxml_node_t *data;
	
	char *filepath = malloc(32);
	char *right = malloc(32);
	char *filename = malloc(32);
	char *p;

	const char *symmkey;
	const char *iv;
	const char *pubkey;
	const char *privkey;
	const char *servername;
	const char *serverpath;
	
	xml = mxmlNewXML("1.0");
	keyring = mxmlNewElement(xml,"keyring");
	
	fp = fopen(keyfile, "r");
	tree = mxmlLoadFile(NULL, fp,MXML_TEXT_CALLBACK);
	fclose(fp);

	for (int i = 4; i < arrlen; i++){
		p = strtok(filerights[i], ":");
    		strcpy(filepath, p);
    		p = strtok(NULL, ":");
	 	strcpy(right, p);
		
		filename = basename(filepath);
		node = mxmlFindElement(tree, tree, "file","path", filepath,MXML_DESCEND);
		node = mxmlFindElement(node,tree,"data",NULL,NULL,MXML_DESCEND);
		if(node != NULL){
		privkey = mxmlElementGetAttr(node, "prikey");
		if(strcmp(privkey,"") != 0){
		
		file = mxmlNewElement(keyring, "file");
		
		mxmlElementSetAttrf(file,"path", "%s", filename);
		data = mxmlNewElement(file, "data");
		
		symmkey = mxmlElementGetAttr(node, "symmkey");
		mxmlElementSetAttrf(data, "symmkey", "%s", symmkey);
	
		iv = mxmlElementGetAttr(node, "iv");
		mxmlElementSetAttrf(data, "iv", "%s", iv);

		pubkey = mxmlElementGetAttr(node, "pubkey");
		mxmlElementSetAttrf(data, "pubkey", "%s", pubkey);

		if(strcmp("w",right) == 0){
			mxmlElementSetAttrf(data, "prikey", "%s", privkey);
			
		}else{
			mxmlElementSetAttrf(data, "prikey", "%s", "");
		}

		servername = mxmlElementGetAttr(node, "servername");
		mxmlElementSetAttrf(data, "servername", "%s", servername);
	

		serverpath = mxmlElementGetAttr(node, "serverpath");
		mxmlElementSetAttrf(data, "serverpath", "%s", serverpath);

		}
		}
    }
	strcat(loadfile,"_SHAREKEY.xml");
	fp = fopen(loadfile, "w");
	mxmlSaveFile(xml, fp, MXML_NO_CALLBACK);
	fclose(fp);
}

void loadSharedKey(char *keyfile, const char *loadfile){
	FILE *fp;
	mxml_node_t *keytree;  
	mxml_node_t *keynode;
	
	mxml_node_t *loadtree;  
   	mxml_node_t *loadnode;
	
	fp = fopen(keyfile, "r");
	keytree = mxmlLoadFile(NULL, fp,MXML_TEXT_CALLBACK);
	fclose(fp);
	
	keynode = mxmlFindElement(keytree, keytree,
                                "keyring",
                                NULL, NULL,
                                MXML_DESCEND);

	fp = fopen(loadfile, "r");
	loadtree = mxmlLoadFile(NULL, fp,MXML_TEXT_CALLBACK);
	fclose(fp);

	loadnode = mxmlFindElement(loadtree, loadtree,
                                "file",
                                NULL, NULL,
                                MXML_DESCEND);

	mxmlAdd(keynode, MXML_ADD_AFTER, NULL, loadnode);

	fp = fopen(keyfile, "w");
	mxmlSaveFile(keytree, fp, MXML_NO_CALLBACK);
	fclose(fp);
}

void revokeFiles(char *keyfile, char *loadfile, char *filerights[], int arrlen){
	FILE *fp;
	mxml_node_t *tree;  
  	mxml_node_t *node;

	mxml_node_t *xml;
	mxml_node_t *keyring;
	mxml_node_t *file;
	mxml_node_t *data;
	
	char *filepath = malloc(32);
	char *right = malloc(32);
	char *filename = malloc(32);
	char *p;

	const char *symmkey;
	const char *iv;
	const char *pubkey;
	const char *privkey;
	const char *servername;
	const char *serverpath;
	
	xml = mxmlNewXML("1.0");
	keyring = mxmlNewElement(xml,"keyring");
	
	

	for (int i = 4; i < arrlen; i++){
	p = strtok(filerights[i], ":");
    	strcpy(filepath, p);
    	p = strtok(NULL, ":");
	 	strcpy(right, p);

		writeKeys(keyfile,filepath);
		//the load has to be done for each file because
		//it changes after each wrrite keys call
		fp = fopen(keyfile, "r");
		tree = mxmlLoadFile(NULL, fp,MXML_TEXT_CALLBACK);
		fclose(fp);

		filename = basename(filepath);
		node = mxmlFindElement(tree, tree, "file",
                           "path", filepath,
                           MXML_DESCEND);
		node = mxmlFindElement(node,tree,"data",NULL,NULL,MXML_DESCEND);
		if(node != NULL){
		file = mxmlNewElement(keyring, "file");
		
		mxmlElementSetAttrf(file,"path", "%s", filename);

		data = mxmlNewElement(file, "data");
		
		
		symmkey = mxmlElementGetAttr(node, "symmkey");
		mxmlElementSetAttrf(data, "symmkey", "%s", symmkey);
	
		iv = mxmlElementGetAttr(node, "iv");
		mxmlElementSetAttrf(data, "iv", "%s", iv);

		pubkey = mxmlElementGetAttr(node, "pubkey");
		mxmlElementSetAttrf(data, "pubkey", "%s", pubkey);

		if(strcmp("w",right) == 0){
			privkey = mxmlElementGetAttr(node, "prikey");
			mxmlElementSetAttrf(data, "prikey", "%s", privkey);
			
		}else{
			mxmlElementSetAttrf(data, "prikey", "%s", "");
		}

		servername = mxmlElementGetAttr(node, "servername");
		mxmlElementSetAttrf(data, "servername", "%s", servername);
	

		serverpath = mxmlElementGetAttr(node, "serverpath");
		mxmlElementSetAttrf(data, "serverpath", "%s", serverpath);

		}
    }
	strcat(loadfile,"_SHAREKEY.xml");
	fp = fopen(loadfile, "w");
	mxmlSaveFile(xml, fp, MXML_NO_CALLBACK);
	fclose(fp);
}

void deleteOldFiles(char *keyfile, char *files[], int arrlen){
	FILE *fp;
	mxml_node_t *tree;  
  	mxml_node_t *node;

	fp = fopen(keyfile, "r");
	tree = mxmlLoadFile(NULL, fp,MXML_TEXT_CALLBACK);
	fclose(fp);

	for (int i = 3; i < arrlen; i++){
		
		node = mxmlFindElement(tree, tree, "file","path", files[i],MXML_DESCEND);
		if(node != NULL){
			mxmlDelete(node);
		}
    }
	fp = fopen(keyfile, "w");
	mxmlSaveFile(tree, fp, MXML_NO_CALLBACK);
	fclose(fp);
}

int main(int argc, char *argv[]){
	char *keyfile;
	char *loadfile;
	keyfile = argv[2];
	loadfile = argv[3];

	if(strcmp(argv[1],"share") == 0){
		shareKeyFile(keyfile, loadfile, argv, argc);
	}else if(strcmp(argv[1],"load") == 0){
		loadSharedKey(keyfile,loadfile);
	}else if(strcmp(argv[1],"revoke") == 0){
		shareKeyFile(keyfile, loadfile, argv, argc);
	}else if(strcmp(argv[1],"delete") == 0){
		deleteOldFiles(keyfile, argv, argc);
	}else{
		printf("===INVALID MODE===\nPlease select either \"share\", \"load\", \"revoke\" or \"delete\"");
	}

	return 0;
	
	
}
