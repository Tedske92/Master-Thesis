#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mxml.h>
#include <libgen.h> 
#include <curl/curl.h>
 
size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

size_t static write_callback_func(void *buffer, size_t size, size_t nmemb,  void *userp)
{
     userp += strlen(userp);  // Skipping to first unpopulated char
     memcpy(userp, buffer, nmemb);  // Populating it.
     return nmemb;
}

char *extractXML(const char *xml, const char *type)
{
    char  *pointer;
    char  *result;
    char  *tail;
    size_t length;

    /* advance the pointer to the = character, and skip the " -> +1 */
    if(type == "url"){
    pointer = strstr(xml, "url=") + strlen("url=") + 1;
    }else if(type == "token"){
    pointer = strstr(xml, "token=") + strlen("token=") + 1;
    }else if(type == "session"){
    pointer = strstr(xml, "session") + strlen("session") + 1;
    }else if(type == "iurl"){
    pointer = strstr(xml, "ii url=") + strlen("ii url=") + 1;
    }

    result  = NULL;
    if (pointer == NULL)
        return NULL;

    length = 0;
    tail = strchr(pointer, ' ');

    if (tail == NULL)
        return NULL;
    /* -1 skip the trailing " */
    length = tail - pointer - 1;
    if (length > 0)
    {
        result = malloc(1 + length);
        if (result == NULL)
            return NULL;
        result[length] = '\0';

        memcpy(result, pointer, length);
    }

    return result;
}

char *getfilePath(char *filename){
  CURL *curl;
  CURLcode res;
  struct curl_httppost *post = NULL;
  struct curl_httppost *last = NULL;
  char *xml = (char *) malloc(4096);
  char *file;

  curl_global_init(CURL_GLOBAL_DEFAULT);
  
  curl = curl_easy_init();
char checkfile[512];
  sprintf(checkfile,"File:%s", filename);
  if(curl) {

   curl_formadd(&post, &last, CURLFORM_COPYNAME, "action",CURLFORM_COPYCONTENTS, "query", CURLFORM_END);

curl_formadd(&post, &last, CURLFORM_COPYNAME, "format",CURLFORM_COPYCONTENTS, "xml", CURLFORM_END);

curl_formadd(&post, &last, CURLFORM_COPYNAME, "prop",CURLFORM_COPYCONTENTS, "imageinfo", CURLFORM_END);

curl_formadd(&post, &last, CURLFORM_COPYNAME, "titles",CURLFORM_COPYCONTENTS, checkfile, CURLFORM_END);

curl_formadd(&post, &last, CURLFORM_COPYNAME, "iiprop",CURLFORM_COPYCONTENTS, "url", CURLFORM_END);
  
   curl_easy_setopt(curl, CURLOPT_URL, "localhost/wikimedia/api.php");
   curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
   curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
   curl_easy_setopt(curl, CURLOPT_WRITEDATA, xml);
  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);

  /* Check for errors */
  if(res != CURLE_OK)
    fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));

   /* always cleanup */
    curl_easy_cleanup(curl);
    curl_formfree(post);
  }
  
  curl_global_cleanup();
  if(strstr(xml,"missing=\"\"") == NULL){
  file = extractXML(xml,"iurl");
	return file;
}
  return NULL;

}

char *getEditToken(const char *newcookie){

  CURL *curl;
  CURLcode res;
  struct curl_httppost *post = NULL;
  struct curl_httppost *last = NULL;
  char *response = (char *) malloc(4096);
  char *token = (char *) malloc(512);
  char *session = (char *) malloc(512);

  char cookie[1024];
  sprintf(cookie,"my_wiki_UserName=WikiUser; my_wiki_session=%s; my_wikiUserID=1", newcookie);

 curl = curl_easy_init();
  
  if(curl){
  
    /* Now specify the POST data */ 
curl_formadd(&post, &last, CURLFORM_COPYNAME, "action",CURLFORM_COPYCONTENTS, "query", CURLFORM_END);
curl_formadd(&post, &last, CURLFORM_COPYNAME, "format",CURLFORM_COPYCONTENTS, "xml", CURLFORM_END);
curl_formadd(&post, &last, CURLFORM_COPYNAME, "meta",CURLFORM_COPYCONTENTS, "tokens", CURLFORM_END);
curl_formadd(&post, &last, CURLFORM_COPYNAME, "type",CURLFORM_COPYCONTENTS, "csrf", CURLFORM_END);

  curl_easy_setopt(curl, CURLOPT_URL, "localhost/wikimedia/api.php");
  curl_easy_setopt(curl, CURLOPT_COOKIE, cookie);
  curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
  curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);



  res = curl_easy_perform(curl);
   // Check for errors 
   if(res != CURLE_OK)
     fprintf(stderr, "curl_easy_perform() failed: %s\n",
             curl_easy_strerror(res));
  
    curl_easy_cleanup(curl);

    curl_formfree(post);
  }
  token = extractXML(response, "token");
  return token;

}

char *clientLogin(const char *token, const char *session){
 
 CURL *curl;
  CURLcode res;
  struct curl_httppost *post = NULL;
  struct curl_httppost *last = NULL;

  char cookie[512];
  sprintf(cookie," my_wiki_session=%s", session);
  
  
  char *retURL = (char *) malloc(512);
  char *response = (char *) malloc(1024);
  char *newsession = (char *) malloc(512);


  curl = curl_easy_init();

  if(curl) {

  curl_formadd(&post, &last, CURLFORM_COPYNAME, "action",CURLFORM_COPYCONTENTS, "clientlogin", CURLFORM_END);

  curl_formadd(&post, &last, CURLFORM_COPYNAME, "format",CURLFORM_COPYCONTENTS, "xml", CURLFORM_END);

  curl_formadd(&post, &last, CURLFORM_COPYNAME, "loginreturnurl",CURLFORM_COPYCONTENTS, "http://example.org", CURLFORM_END);

  curl_formadd(&post, &last, CURLFORM_COPYNAME, "logintoken",CURLFORM_COPYCONTENTS, token, CURLFORM_END);

  curl_formadd(&post, &last, CURLFORM_COPYNAME, "username",CURLFORM_COPYCONTENTS, "WikiUser", CURLFORM_END);

  curl_formadd(&post, &last, CURLFORM_COPYNAME, "password",CURLFORM_COPYCONTENTS, "password1234", CURLFORM_END);

  curl_easy_setopt(curl, CURLOPT_URL, "localhost/wikimedia/api.php");
  curl_easy_setopt(curl, CURLOPT_COOKIE, cookie);
  curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
  curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
 
   res = curl_easy_perform(curl);
   // Check for errors 
   if(res != CURLE_OK)
     fprintf(stderr, "curl_easy_perform() failed: %s\n",
             curl_easy_strerror(res));
    
    // always cleanup  
    curl_easy_cleanup(curl);

    curl_formfree(post);
  }
  curl_global_cleanup();
  newsession = extractXML(response, "session");
  return newsession;
}



char *getSession()
{
  CURL *curl;
  CURLcode res;
  struct curl_httppost *post = NULL;
  struct curl_httppost *last = NULL;
  char *xml = (char *) malloc(1024);
  char *token = (char *) malloc(512);
  char *session = (char *) malloc(512);

  curl = curl_easy_init();
  
if(curl){
   
 curl_formadd(&post, &last, CURLFORM_COPYNAME, "action",CURLFORM_COPYCONTENTS, "query", CURLFORM_END);
   curl_formadd(&post, &last, CURLFORM_COPYNAME, "format",CURLFORM_COPYCONTENTS, "xml", CURLFORM_END);
   curl_formadd(&post, &last, CURLFORM_COPYNAME, "meta",CURLFORM_COPYCONTENTS, "tokens", CURLFORM_END);
   curl_formadd(&post, &last, CURLFORM_COPYNAME, "type",CURLFORM_COPYCONTENTS, "login", CURLFORM_END);

 curl_easy_setopt(curl, CURLOPT_URL, "localhost/wikimedia/api.php");
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, xml);

 
    res = curl_easy_perform(curl);
    
   if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    session = extractXML(xml, "session");
    token = extractXML(xml,"token");
    
    curl_easy_cleanup(curl);
    curl_formfree(post);
  }
  curl_global_cleanup();
  
  return clientLogin(token, session);
  
}

/*int logOut(){

}*/



int download(const char *localPath, const char *serverPath)
{
  CURL *curl_handle;
  FILE *pagefile;
 
  //tempfile decrypt to local path
  //after download mayby change version number in keyring, if added
 
  /* init the curl session */ 
  curl_handle = curl_easy_init();
 
  /* set URL to get here */ 
  curl_easy_setopt(curl_handle, CURLOPT_URL, serverPath);
 
  /* Switch on full protocol/debug output while testing */ 
  curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);
 
  /* disable progress meter, set to 0L to enable and disable debug output */ 
  curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
 
  /* send all data to this function  */ 
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);
 
  /* open the file */ 
  pagefile = fopen(localPath, "wb");
  if(pagefile) {
 
    /* write the page body to this file handle */ 
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, pagefile);
 
    /* get it! */ 
    curl_easy_perform(curl_handle);
 
 
    /* close the header file */ 
    fclose(pagefile);
  }
 
  /* cleanup curl stuff */ 
  curl_easy_cleanup(curl_handle);
 
  return 0;
}

char *upload(const char *localPath, const char *serverName, const char *session, const char *token, const char *comment)
{
  CURL *curl;
  CURLcode res;
  struct curl_httppost* post = NULL;
  struct curl_httppost* last = NULL;
  char *response = (char *) malloc(4096);

char cookie[512];
  sprintf(cookie,"my_wiki_UserName=WikiUser; my_wiki_session=%s; my_wikiUserID=1", session);


 curl = curl_easy_init();
 if(curl){
 /* Add simple name/content section */
 curl_formadd(&post, &last, CURLFORM_COPYNAME, "action",
              CURLFORM_COPYCONTENTS, "upload", CURLFORM_END);

 curl_formadd(&post, &last, CURLFORM_COPYNAME, "format",
              CURLFORM_COPYCONTENTS, "xml", CURLFORM_END);

 curl_formadd(&post, &last, CURLFORM_COPYNAME, "ignorewarnings",
              CURLFORM_COPYCONTENTS, "1", CURLFORM_END);

 curl_formadd(&post, &last, CURLFORM_COPYNAME, "filename",
              CURLFORM_COPYCONTENTS, serverName, CURLFORM_END);

curl_formadd(&post, &last, CURLFORM_COPYNAME, "comment",
              CURLFORM_COPYCONTENTS, comment, CURLFORM_END);

curl_formadd(&post, &last, CURLFORM_COPYNAME, "token",
              CURLFORM_COPYCONTENTS, token, CURLFORM_END);

curl_formadd(&post, &last,
            CURLFORM_COPYNAME, "file",
            CURLFORM_FILE, localPath, CURLFORM_END);
 

  curl_easy_setopt(curl, CURLOPT_URL, "localhost/wikimedia/api.php");
  curl_easy_setopt(curl, CURLOPT_COOKIE, cookie);
  curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);


   res = curl_easy_perform(curl);
  /* Check for errors */
  if(res != CURLE_OK)
    fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
   /* always cleanup */
    curl_easy_cleanup(curl);
    curl_formfree(post);
  }

  curl_global_cleanup();
  return response;
}

