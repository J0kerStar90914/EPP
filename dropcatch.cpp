/**
  gcc -o main main.cpp -lssl -lcrypto
  gcc -Wall -I/usr/include/cppconn -o main main.cpp -L/usr/lib -lmysqlcppconn -lssl -lcrypto -lstdc++ -pthread
  */
#include <stdio.h>
#include <iostream>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <signal.h>
#include <mysql_connection.h>
#include <sys/stat.h> // stat
#include <errno.h>    // errno, ENOENT, EEXIST
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include "Log.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <libconfig.h++>
#include <ctime>
#include <systemd/sd-daemon.h>
#define FAIL    -1
#define IN
#define OUT
using namespace std;
using namespace libconfig;
/***********************************************************************
 * Global Function definitions
 ***********************************************************************/
void  SIGINT_handler(int);         /* for SIGINT                    */
void  SIGHUP_handler(int);         /* for SIGHUP                  */
void  SIGKILL_handler(int);        /* for SIGKILL                  */
int OpenConnection(const char *hostname, int port);		/* This if function for socket connection*/
SSL_CTX* InitCTX(void);			/*init SSL_CTX structure*/
void ShowCerts(SSL* ssl);		/*show server's certificate*/
void log_save(int type, const char *message);  /*save log to file*/
void makeChar(unsigned int n, char*p);  /*make size value n to p*/
int getInt(char*p);					/*extract size value*/
int checkResult(char *presult);   /*check result from string*/

int createLoginXML(char *p);	/*create login xml*/
int createRegistrantXML(char *p,const char *registant,const char* name,const char *org,const char* street,const char* city,const char* postcode,const char* country,const char* phone,const char* email);
int createHelloXML(char *p);  /*create hello xml*/
int createDomainXML(char *p, const char* domain, const char* registrant); /*create domain xml*/
long long int mi(int y, int m, int d, int h, int mm, int ss, long long int nanosec);/*convert date to second*/
long long int timeSub(const char *time1);		/*substract time with current time*/
void *epp_thread_body(void * arg);	/*main thread body*/
int read_conf_file();				/*read conf file*/

/************************************************************************************
 *Global variable definitions
 ************************************************************************************/
int g_threadworking=0;				/*thread working variable*/
string db_host;				/*mysql database hostname*/
string db_user;				/*mysql database username*/
string db_pass;				/*mysql database password*/
string db_name;				/*mysql database name*/
string db_port = "3306";				/*mysql database port*/
string epp_host;				/*EPP server name*/
int epp_port;				/*EPP server port*/
string epp_password;			/*EPP Client password*/
string epp_clid;			/*EPP client ID*/
float prepare_time = 1;			/*send create xml start time*/
float final_time = 0.01;			/*send interval*/
string log_level = "DEBUG|INFO|WARN|ERROR";			/*log level*/
string table_drop;			/*drop table name*/
string table_catch;			/*catch table name*/
char *prg;							/*program's name for restart*/
char curtime_string[25] = {0};		/*current time string format is YYYY-MM-dd hh:mm:ss*/
char conf_file_name[260] = {0};		/*config file name*/
int log_level_flags[4]={0};	/*log level flags*/
char sys_user[50] = "dropcatch";		/* System user*/
int nwaiting_ids[100] = {0};	/*waiting domain registrant.*/
int nwaiting_cnt = 0;		/*waiting count*/
/***********************************************************************
 * This function get current time and convert it to UTC.
 * save time as string to curtime_string
 * format is YYYY-MM-dd hh:mm:ss
 ************************************************************************/
void calc_current_time() {
    time_t curtime = time(0);		/*Current time*/
    tm *gmtm = gmtime(&curtime);  /*UTC Current time*/

    memset(curtime_string, 0, 25);
    //gmtm->tm_year, gmtm->tm_mon, gmtm->tm_mday, gmtm->tm_hour, gmtm->tm_min, gmtm->tm_sec
    sprintf(curtime_string, "%04d %02d %02d %02d %02d %02d", gmtm->tm_year+1900, gmtm->tm_mon+1, gmtm->tm_mday, gmtm->tm_hour, gmtm->tm_min, gmtm->tm_sec);
}
/***********************************************************************
 * This function get length from string.
 * 4 byte are whole message length.
 * so get 4 bytes and convert it integer.
 * it is big endian, not little endian, 0x1234 is 00 00 12 34,
 * not 34 12 00 00.
 ************************************************************************/
int getInt(IN char*p) {
    unsigned int ch0 = (unsigned char)p[0];	/*Get First byte*/
    unsigned int ch1 = (unsigned char)p[1]; 	/*Get Second byte*/
    unsigned int ch2 = (unsigned char)p[2];   /*Get third byte*/
    unsigned int ch3 = (unsigned char)p[3];   /*Get fourth byte*/
    ch0 = (ch0 << 24) + (ch1 << 16)+ (ch2 << 8) + ch3; /*get integer.*/
    return ch0;
}
/*************************************************************************
 * This function do reverse operation with getInt
 * with size n make 4 bytes header.
 * big Endian format. 0x1234 => p[0]=0, p[1]=0, p[2]=0x12, p[3]=0x34;
 **************************************************************************/
void makeChar(IN unsigned int n, OUT char*p) {
    p[3] = n & 0xFF;							/*integer lowest bytte*/
    p[2] = (n >> 8) & 0xFF;					/* second byte*/
    p[1] = (n >> 16) & 0xFF;					/* third byte*/
    p[0] = (n >> 24) & 0xFF;					/* MSB byte*/
}
/*************************************************************************
* Get time in nano second.
* This function uses for estimating time for running and creating
**************************************************************************/
long long int get_tick() {
  struct timespec ts;
  timespec_get(&ts, TIME_UTC);
  long long int t;
  t = ts.tv_sec * 1000000000 + ts.tv_nsec;
  return t;
}
/*************************************************************************
 * This function check result in string.
 * when success EPP server returns code="1000"
 * when failed return other value like "2032"(domain already registered)
 **************************************************************************/
int checkResult(IN char *presult) {
    if(strstr(presult, "1000") != NULL) {
        //successfully runned
        //code="1000"
        //printf("1000 found\n");
        return 1;
    }
    else if(strstr(presult, "2032") != NULL) {
        //aleready registered.
        //printf("2302 found\n");
        return 0;
    }

    return 0;
}

/***********************************************************************
 * This function create xml string to login
 * after server say greeting, we have to login before any command performs
 * p is completed login string. using clid and password, we can log in.
 ************************************************************************/
int createLoginXML(OUT char *p) {
    char loginxml[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd\">\n\t<command>\n\t\t<login>\n\t\t\t<clID>%s</clID>\n\t\t\t<pw>%s</pw>\n\t\t\t<options>\n\t\t\t\t<version>1.0</version>\n\t\t\t\t<lang>en</lang>\n\t\t\t</options>\n\t\t\t<svcs>\n\t\t\t\t<objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>\n\t\t\t\t<objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>\n\t\t\t\t<objURI>urn:ietf:params:xml:ns:host-1.0</objURI>\n\t\t\t</svcs>\n\t\t</login>\n\t\t<clTRID>ABC-112233445</clTRID>\n\t</command>\n</epp>";
    char temp[1000] = {0}; /*XML log template*/
    int n;

    sprintf(temp, loginxml, epp_clid.c_str(), epp_password.c_str()); /*using clid, password get completed login string*/
    n = strlen(temp);				/*calculate length*/
    makeChar(n + 4, p);			/*calculate header*/
    memcpy(p+4, temp, n);			/*append body*/

    return n+4;					/*return value is length*/
}
/***********************************************************************
 * This function create registrant xml.
 * to create domain, we have to use registrant id and registrant has to be created before use.
 * to create registrant, we need many informations about him/her
 * p is completed login string.
 * registant is registant_id(generate by random)
 * name is registant name, org is registant's orgnizatiom.
 * street is street who registrant live, city is same
 * post code is his/her post code, country is country who lives. phone is phone number
 * email is email number
 ************************************************************************/
int createRegistrantXML(OUT char *p,IN const char *registant,IN const char* name,IN const char *org,IN const char* street,IN const char* city,IN const char* postcode,IN const char* country,IN const char* phone,IN const char* email) {
    char crxml[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"\n\txmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n\txsi:schemaLocation=\"urn:ietf:params:xml:ns:epp-1.0\n\tepp-1.0.xsd\">\n\t<command>\n\t\t<create>\n\t\t\t<contact:create\n\t\t\t\txmlns:contact=\"urn:ietf:params:xml:ns:contact-1.0\"\n\t\t\t\txsi:schemaLocation=\"urn:ietf:params:xml:ns:contact-1.0\n\t\t\t\tcontact-1.0.xsd\">\n\t\t\t\t<contact:id>%s</contact:id>\n\t\t\t\t<contact:postalInfo type=\"loc\">\n\t\t\t\t\t<contact:name>%s</contact:name>\n\t\t\t\t\t<contact:org>%s</contact:org>\n\t\t\t\t\t<contact:addr>\n\t\t\t\t\t\t<contact:street>%s</contact:street>\n\t\t\t\t\t\t<contact:street>%s</contact:street>\n\t\t\t\t\t\t<contact:city>%s</contact:city>\n\t\t\t\t\t\t<contact:sp>%s</contact:sp>\n\t\t\t\t\t\t<contact:pc>%s</contact:pc>\n\t\t\t\t\t\t<contact:cc>%s</contact:cc>\n\t\t\t\t\t</contact:addr>\n\t\t\t\t</contact:postalInfo>\n\t\t\t\t<contact:voice>%s</contact:voice>\n\t\t\t\t<contact:email>%s</contact:email>\n\t\t\t\t<contact:authInfo>\n\t\t\t\t\t<contact:pw>authinfo</contact:pw>\n\t\t\t\t</contact:authInfo>\n\t\t\t</contact:create>\n\t\t</create>\n\t</command>\n</epp>";
    char temp[2000] = {0}; /*xMl template for create registant*/
    int n;
    /*Create temporary string that is xml body*/
    sprintf(temp, crxml, registant, name, org, street, "", city, "England", postcode, country, phone, email);
    n = strlen(temp);	/*xml body length*/
    makeChar(n + 4, p); /*make header of xml*/
    memcpy(p+4, temp, n); /*copy body*/

    return n+4;			/*return whole length*/
}
/***********************************************************************
 * This function create hello xml string
 * we send hello xml every 50 min, so always communication keep open
 * hello xml template is short
 ************************************************************************/
int createHelloXML(OUT char *p) {
    char helloxml[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"\n\txmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n\txsi:schemaLocation=\"urn:ietf:params:xml:ns:epp-1.0\n\tepp-1.0.xsd\">\n\t<hello/>\n\t</epp>";
    int n = strlen(helloxml); /*xml body length*/
    makeChar(n + 4, p);   /*make header of xml*/
    memcpy(p+4, helloxml, n); /*copy body*/
    return n+4; /*return whole length*/
}
/***********************************************************************
 * This function create domain xml string
 * after domain name, and registrant id get, we can create domain
 * from template, we make completed xml string.
 ************************************************************************/
int createDomainXML(OUT char *p, IN const char* domain, IN const char* registrant) {
    char crxml[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"\n\txmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n\txsi:schemaLocation=\"urn:ietf:params:xml:ns:epp-1.0\n\tepp-1.0.xsd\">\n\t<command>\n\t\t<create>\n\t\t\t<domain:create\n\t\t\t\txmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"\n\t\t\t\txsi:schemaLocation=\"urn:ietf:params:xml:ns:domain-1.0\n\t\t\t\tdomain-1.0.xsd\">\n\t\t\t\t<domain:name>%s</domain:name>\n\t\t\t\t<domain:period unit=\"y\">2</domain:period>\n\t\t\t\t<domain:registrant>%s</domain:registrant>\n\t\t\t\t<domain:authInfo>\n\t\t\t\t\t<domain:pw>**********</domain:pw>\n\t\t\t\t</domain:authInfo>\n\t\t\t</domain:create>\n\t\t</create>\n\t\t<clTRID>abcde1234566</clTRID>\n\t</command>\n</epp>";
    char temp[2000] = {0};
    int n;
    /*Create temporary string that is xml body*/
    sprintf(temp, crxml, domain, registrant);
    n = strlen(temp);   /*xml body length*/
    makeChar(n + 4, p);   /*make header of xml*/
    memcpy(p+4, temp, n); /*copy body*/

    return n+4; /*return whole length*/
}
/***********************************************************************
 * This function convert date to second
 * we have to calculate timer substraction continously.
 * get second from date values.
 * y = year, m- month, d- day, h - hour, mm -min, ss- second
 ************************************************************************/
long long int mi(IN int y, IN int m, IN int d, IN int h, IN int mm, IN int ss, long long int nanosec) {
    m = (m + 9) % 12;
    y = y - m/10;
    long long int dd = 365*y + y/4 - y/100 + y/400 + (m*306 + 5)/10 + ( d - 1 );
    dd = dd * 86400 + h * 3600 + mm*60 + ss;
    dd = dd * 1000000000 + nanosec;
    return dd;
}
/***********************************************************************
 * This function convert substract time
 * time is in format YYYY-MM-dd hh:mm:ss
 * so we extract values from string and substrct using above function
 * we use UTC time
 ************************************************************************/
long long int timeSub(IN const char *time1) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    tm *gmtm = gmtime(&ts.tv_sec);

    int yy,mm,dd, hh, mmin, ss;
    char tmp[5] = {0};
    memcpy(tmp, time1, 4);
    yy = atoi(tmp);				/*Extract year from string time1*/

    memset(tmp, 0, 5);
    memcpy(tmp, time1+5, 2);     /*Extract month from string time1*/
    mm = atoi(tmp);

    memset(tmp, 0, 5);
    memcpy(tmp, time1+8, 2);		/*Extract date from string time1*/
    dd = atoi(tmp);

    memset(tmp, 0, 5);
    memcpy(tmp, time1+11, 2);		/*Extract hour from string time1*/
    hh = atoi(tmp);

    memset(tmp, 0, 5);
    memcpy(tmp, time1+14, 2);		/*Extract minute from string time1*/
    mmin = atoi(tmp);

    memset(tmp, 0, 5);
    memcpy(tmp, time1+17, 2);		/*Extract second from string time1*/
    ss = atoi(tmp);
    long long int nsecs = mi(yy - 1900, mm - 1, dd, hh, mmin, ss, 0) - mi(gmtm->tm_year, gmtm->tm_mon, gmtm->tm_mday, gmtm->tm_hour, gmtm->tm_min, gmtm->tm_sec, ts.tv_nsec) ;		/*substract with second*/
    return nsecs;							/*return second diffrence*/
}
/**********************************************************************
*  check waiting ids and if new id then save it to log file.
*  then add new id to waiting_ids array
**************************************************************************/
void check_ids(int id, string domain) {
  int i = 0;
  int exist = 0;
  char buf[200] = {0};
  for(i = 0; i < nwaiting_cnt; i++) {
    if(nwaiting_ids[i] == id) {
      exist = 1;
      break;
    }
  }
  if(exist == 0) {
    sprintf(buf, "Found domain to catch: %s", domain.c_str());
    LOG_INFO(buf);
    nwaiting_ids[nwaiting_cnt++] = id;
  }
}
/*************************************************************
*  save domain_catch table contentto log file.
*  read all conttent where it is waiting or failed or success.
*  and grab waiting status
**************************************************************/
void save_domain_catch_to_log(sql::Connection *con) {
  sql::Statement *stmt;
  sql::ResultSet *res;
  char buf[0x1000];
  stmt = con->createStatement();
  memset(buf, 0, 0x1000);
  sprintf(buf, "SELECT dc.id, dd.domain, dd.dropping, dd.roid, dr.id as drid, dc.status FROM %s as dc INNER JOIN %s as dd ON dc.domain_drop_id=dd.id INNER JOIN domain_registrants as dr ON dr.id=dc.registrant_id;", table_catch.c_str(), table_drop.c_str());
  res = stmt->executeQuery(buf);	/*mysql get string*/
  while (res->next()) {
    string id = res->getString(1);		/*id of drop_cathes*/
    string domain = res->getString(2);	/*domain to register*/
    string dropping = res->getString(3);	/*expired time*/
    string roid = res->getString(4);	/*repo id*/
    string drid = res->getString(5);	/*domain_registrants id*/
    string status = res->getString(6);
    if(status == "waiting") {
      nwaiting_ids[nwaiting_cnt++] = stoi(id);
    }
    sprintf(buf, "Domains in table_catch : %s, status : %s", domain.c_str(), status.c_str());
    LOG_INFO(buf);
  }
}
/***********************************************************************
 * This function is Main thread controller body
 * work as follows.
 1. init mysql and connect
 2. init ssl and connect to EPP server
 3. receive greeting message from server
 4. send login xml to server and login.
 5. check mysql state and get relative informations from domain_catch, domain_drop,domain_registrants table.
 6. compare current time with domain_drops dropping time.
 7. if registrant not registed, before 20min, send create registrant command
 8. After success, update domain_registrants table.
 9. before 20 second, sleep time changed 1 and continusly try to send CREATE command.
 10. After success, update domain_catches table.
 11. send hello xml every 50 mins to keep communication open.
 12. can finished by signals
 *
 important point.
 first we have to receive greeing message from server.
 4 bytes are length field and big endian.

 ************************************************************************/
void *epp_thread_body(IN void * arg) {

    sql::Driver *driver;		/*mysql variables*/
    sql::Connection *con;    /*mysql variables*/
    sql::Statement *stmt;    /*mysql variables*/
    sql::ResultSet *res;     /*mysql variables*/

    sql::ConnectOptionsMap connection_properties;

    connection_properties["hostName"] = db_host;	/*connect to mysql using config settings.*/
    connection_properties["userName"] = db_user;
    connection_properties["password"] = db_pass;
    connection_properties["schema"] = db_name;
    connection_properties["port"] = stoi(db_port);
    connection_properties["OPT_RECONNECT"] = true;

    try {
        driver = get_driver_instance();
        con = driver->connect(connection_properties);		/*mysql connect*/
        if(con == NULL) {
          LOG_ERROR("MariaDB connection failed.");
          exit(3);
        }
    } catch (sql::SQLException &e) {
        fprintf(stderr, "Unable to connect to SQL server: %s\n", e.what());
        exit(3);
    }

    LOG_INFO("MariaDB connection success.");
    save_domain_catch_to_log(con);
    fprintf(stdout, "Startup successful.\n");
    sd_notify(0, "READY=1");
    SSL_CTX *ctx;						/*structure for Ssl communication*/
    int server;						/*socket varialbe*/
    SSL *ssl;							/*SSL layer varialbe combined with server socket*/

    char buf[0x1000] = {0};			/*variable for thread*/
    int bytes, nsecs = 0;				/*temp variable for read byte and last second*/
    int ball = 0;						/*temp variable for all read bytes*/
    int nheader = 0;					/*header length*/
    int nsuccess = 0;					/*success flag*/

    int attentiontime = 0;			/*thread running every 5 ssecond and if attention flag set then work as 1 second*/
    int nsleeptime=prepare_time * 1000000;	/*sleep time in ms*/
    SSL_library_init();			/*init ssl*/

    ctx = InitCTX();				/*init structure*/
    server = OpenConnection(epp_host.c_str(), epp_port);	/*socket connection established*/
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */

    if ( SSL_connect(ssl) == FAIL ) {  /* perform the connection */
        ERR_print_errors_fp(stderr);
        LOG_ERROR("EPP server connection failed.");
        exit(4);
    }
    LOG_WARNING("EPP server connection.");
    //printf("connected with %s encrytion\n",SSL_get_cipher(ssl));
    ShowCerts(ssl);				/*show server cerificate*/
    ball = 0;					/*all received byte*/
    bytes = 0;				/*one time receivedbyte*/

    while(1) {
        memset(buf, 0, 0x1000);
        bytes = SSL_read(ssl, buf,0x1000); // get reply & decrypt
        buf[bytes] = 0;
        ball+= bytes;					/*add to all received byte*/
        if(nheader == 0)
            nheader = getInt(buf);		/*get header*/
        //printf("Received: \"%s\"\n",buf+4);
        if(ball==nheader)
            break;
    }

    //printf("Greeting Message Received.\n");
    int nn = createLoginXML(buf);		/*time to try login*/
    nheader = 0;
    ball = 0;
    nsuccess = 0;
    bytes = SSL_write(ssl,buf,nn);	/*write login body*/

    LOG_DEBUG("send data to server.");
    while(1) {
        usleep(50000);
        memset(buf, 0, 0x1000);
        //printf("read starting.\n");

        bytes = SSL_read(ssl, buf, 0x1000);	/*ready by ssl*/
        buf[bytes]=0;
        ball += bytes;

        if(nheader == 0) {
            nheader = getInt(buf);	/*first segmant received, then ret header and check*/
            nn = checkResult(buf+4);
        }
        else
            nn = checkResult(buf);
        //printf("%s",buf+4);
        if(nn && nsuccess == 0)		/*how result of login*/
            nsuccess =1;
        //printf("%d : %d", ball, nheader);
        if(nheader == ball)
            break;
    }
    if(nsuccess == 1) {
        //printf("Login success\n");		/*display login*/
        LOG_DEBUG("Login success.");
    }
    else {
        //printf("Login failure\n");
        LOG_DEBUG("Login failed.");
        exit(4);
    }
    nsecs = 0;
    char tempbuf[20]={0};
    srand(time(0));
    long long int nsecbefore, ll;

    while(g_threadworking) {			/*thread working body*/
        nsleeptime = attentiontime > 0 ? final_time * 1000000 : prepare_time*1000000;/*sleep 1 when prepare domain registering, sleep 5 normal*/
        usleep(nsleeptime);				/*thread sleep*/
        nsecs += nsleeptime / 1000000;			/*calculate whole sleep time*/
        attentiontime = attentiontime > 0 ? attentiontime - nsleeptime : attentiontime;

        //printf("sleep time: %dms\n", nsleeptime / 1000);
        stmt = con->createStatement();
        memset(buf, 0, 0x1000);
        sprintf(buf, "SELECT dc.id, dd.domain, dd.dropping, dd.roid, dr.id as drid, dr.reg_id, dr.org, dr.disclose_name, dr.street,dr.city, dr.postcode, dr.country, dr.disclose_address, dr.telephone, dr.email FROM %s as dc INNER JOIN %s as dd ON dc.domain_drop_id=dd.id INNER JOIN domain_registrants as dr ON dr.id=dc.registrant_id WHERE dc.status='waiting';", table_catch.c_str(), table_drop.c_str());
        res = stmt->executeQuery(buf);	/*mysql get string*/
        while (res->next()) {
            string id = res->getString(1);		/*id of drop_cathes*/
            string domain = res->getString(2);	/*domain to register*/
            string dropping = res->getString(3);	/*expired time*/
            string roid = res->getString(4);	/*repo id*/
            string drid = res->getString(5);	/*domain_registrants id*/
            string reg_id = res->getString(6);	/*register id*/
            string org = res->getString(7);		/*orgnizatiom*/
            string name = res->getString(8);		/*name*/
            string street = res->getString(9);		/*street*/
            string city = res->getString(10);	/*city*/
            string postcode = res->getString(11);  /*post code*/
            string country = res->getString(12);	/*country*/
            string disclose_address = res->getString(13);	/*disclose addr*/
            string telephone = res->getString(14);		/*telephone*/
            string email = res->getString(15);		/*email*/
            check_ids(stoi(id), domain);
            nsecbefore = timeSub(dropping.c_str()) / 1000;	/*time minus in ms*/
            //printf("%lld second remaining.\n", nsecbefore/1000000);
            if(reg_id.length() == 0) { //It need register first
                if(nsecbefore < 1200000000) {/*before 1200s= 20min, we have to register registrant*/
                    int nr=rand() % 100000 + 100000;	/*randome number by rand()*/
                    sprintf(tempbuf, "AZYXW%d",nr+atoi(drid.c_str()));	/*generate random id*/
                    //printf("Gen registra: %s\n" ,tempbuf);	/*print id*/
                    memset(buf, 0, 0x1000);	/*create registrant xml from function*/
                    nn = createRegistrantXML(buf, tempbuf, name.c_str(),org.c_str(),street.c_str(),city.c_str(),postcode.c_str(), country.c_str(), telephone.c_str(), email.c_str());
                    bytes = SSL_write(ssl,buf,nn);	/*write xml string*/
                    ball = 0; nheader= 0;nsuccess = 0;	/*init variables*/
                    while(1) {
                        usleep(5000);
                        memset(buf, 0, 0x1000);
                        //printf("create registra read starting again.\n");

                        bytes = SSL_read(ssl, buf, 0x1000);	/*read data */
                        buf[bytes]=0;
                        ball += bytes;

                        if(nheader == 0) {
                            nheader = getInt(buf);		/*get message size and header length*/
                            nn = checkResult(buf+4);
                        }
                        else
                            nn = checkResult(buf);
                        if(nn && nsuccess == 0)
                            nsuccess =1;
                        //printf("%d : %s", ball, buf+4);
                        if(nheader == ball)				/*if read all ,then break*/
                            break;
                    }
                    if(nsuccess==1) {
                        //printf("create registrant success.\n");	/*save status to domain_registrants*/
                        memset(buf, 0, 0x1000);
                        sprintf(buf, "UPDATE domain_registrants SET reg_id='%s' WHERE id='%s'", tempbuf, drid.c_str());
                        sql::Statement *stmp = con->createStatement();
                        stmp->execute(buf);
                        delete stmp;
                    }
                    //else
                        //printf("create registrant failed.\n");

                    //printf("Updated mysql database : %s\n",buf);
                    continue;
                }
            }
            if(nsecbefore < prepare_time*1000000 + 1000) {
                if(attentiontime < prepare_time*1000000) /*set attention time, thread will work sleep 1 until this time passed*/
                    attentiontime += prepare_time*1000000; /*we need to pay attention before 15 sec after 5 sec.*/
            }
        //ll = get_tick();
            //printf("time2: %lld\n",ll);

            if(nsecbefore <=0) { //expired and send create command
                //ll=get_tick();
                //printf("domain create start.\n");
                memset(buf, 0, 0x1000);
                nn = createDomainXML(buf, domain.c_str(),reg_id.c_str());	/*create domain xml*/
                ll = get_tick();
                bytes = SSL_write(ssl,buf,nn);	/*write xml*/
                //for(i=0;i<nn;i++) {
                //  printf("%c", buf[i]);
                //}
                memset(buf, 0, 0x1000);
                sprintf(buf, "daemon register attempt start at : %lldms", ll/1000000);
                ball = 0; nheader= 0;nsuccess = 0;	/*init variabls*/
                LOG_INFO(buf);
                while(1) {
                    //usleep(5000);
                    memset(buf, 0, 0x1000);
                    //printf("domain create read starting again.\n");

                    bytes = SSL_read(ssl, buf, 0x1000);	/*read xmls*/
                    buf[bytes]=0;
                    ball += bytes;
                    if(nheader == 0) {
                        nheader = getInt(buf);		/*get header and check result*/
                        nn = checkResult(buf+4);
                    }
                    else
                        nn = checkResult(buf);
                    if(nn && nsuccess == 0)
                        nsuccess =1;
                    if(nheader == ball)		/*if all read break;*/
                        break;
                }

                sql::Statement *stmp = con->createStatement();
                calc_current_time();
                long long int ln = get_tick();
                if(nsuccess == 1) {
                    memset(buf, 0, 0x1000);
                    sprintf(buf, "daemon register success. time spent is : %lld ms.", (ln-ll)/1000000);
                    //printf("domain create success\n");		/*save state to domain_catches*/
                    LOG_INFO(buf);
                    memset(buf, 0, 0x1000);
                    sprintf(buf, "UPDATE %s SET status='success', updated_at='%s' WHERE id='%s'",table_catch.c_str(),curtime_string, id.c_str());
                }
                else {
                    memset(buf, 0, 0x1000);
                    sprintf(buf, "daemon register fail. time spent is : %lld ms.", (ln-ll)/1000000);
                    //printf("domain already exist or failed.\n");
                    LOG_INFO(buf);
                    memset(buf, 0, 0x1000);
                    sprintf(buf, "UPDATE %s SET status='failed', updated_at='%s' WHERE id='%s'",table_catch.c_str(),curtime_string, id.c_str());
                }
                //printf(buf);
                stmp->execute(buf);
                delete stmp;

            }
        }
        if(nsecs >=3000 ) { //Send hello every 50 minutes to keep communication open
            memset(buf, 0, 0x1000);
            nn = createHelloXML(buf);		/*create hello xml*/
            bytes = SSL_write(ssl,buf,nn);	/*send xml string*/
            ball = 0; nheader= 0;
            while(1) {
                usleep(5000);
                memset(buf, 0, 0x1000);
                //printf("read starting again.\n");

                bytes = SSL_read(ssl, buf, 0x1000);	/*read reply(greeting) message*/
                buf[bytes]=0;
                ball += bytes;
                if(nheader == 0)
                    nheader = getInt(buf);		/*get header*/
                //printf("%d : %d", ball, nheader);
                if(nheader == ball)
                    break;
            }
            //printf("Did hello again.\n");
            nsecs = 0;
        }
        delete stmt;
    }
    //printf("main thread ending.\n");
    delete res;	/*remove mysql handlers*/
    delete con;
    LOG_WARNING("EPP disconnection.");
    SSL_free(ssl);        /* release connection state */
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    LOG_WARNING("MariaDB disconnection.");
    return NULL;
}
/***********************************************************************
 * This function open socket connecttion to client
 * using hostname and port it connect and return socket id
 ************************************************************************/
int OpenConnection(IN const char *hostname, IN int port)
{
    int sd;
    struct hostent *host;			/*host addr strucut*/
    struct sockaddr_in addr;   /*sockaddr_in struct*/
    if ( (host = gethostbyname(hostname)) == NULL )
    {						/*get correct host name*/
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);	/*init structure and connect*/
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
/***********************************************************************
 * This function init SSL_CTX structure.
 * create openssl algorithms and clientmethod.
 * verify locations too.
 ************************************************************************/
SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv23_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (!SSL_CTX_load_verify_locations(ctx,"c3.pem","/etc/ssl/certs/"))
    {
        SSL_CTX_free(ctx);
        exit(-1);
    }
    return ctx;
}
/***********************************************************************
 * This function show certificate of file.
 * using ssl socket, it get server information
 * SSL get_peer_certificate function used.
 ************************************************************************/
void ShowCerts(IN SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        //printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        //printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        //printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}
/*****************************************************************************
* Function for value missing.
*******************************************************************************/
void check_config_value_missing(IN const char*name, IN string psval) {
  if(psval.length() == 0) {
    fprintf(stderr, "Missing config value for %s\n", name);
    exit(2);
  }
}
/*****************************************************************************
* Function for log file save
*******************************************************************************/
void save_to_log_in_start(IN const char *field, IN string value) {
  char tmp[300] = {0};
  int len = value.length();
  if(strcmp(field, "db.password") == 0 || strcmp(field, "epp.secret") == 0)
    sprintf(tmp, "%s: %c********%c", field, value[0], value[len-1]);
  else
    sprintf(tmp, "%s: %s", field, value.c_str());
  LOG_INFO(tmp);
}

inline bool file_exist_check (const std::string& name) {
  struct stat buffer;
  return (stat (name.c_str(), &buffer) == 0);
}
/***********************************************************************
 * This function read config file/
 * file name is hardcoded and epp.conf
 * if file not found, we can not use program
 * using fprintf we read line by line.
 ************************************************************************/
int read_conf_file() {
    libconfig::Config config;
    bool exist = file_exist_check (conf_file_name);
    if(exist == false) {
        return 0;
    }
    config.readFile(conf_file_name);
    const Setting& root = config.getRoot();
    const Setting &db = root["db"];
    const Setting &table = db[5];

    const Setting &epp= root["epp"];
    const Setting &log = root["log"];
    const Setting &app = root["app"];
    char tmp[10] = {0};
    /*Very important field*/
    db.lookupValue("hostname", db_host);	/*read db_hostname*/
    check_config_value_missing("db.hostname", db_host);

    db.lookupValue("username", db_user);	/*read db_username*/
    check_config_value_missing("db.username", db_user);

    db.lookupValue("password", db_pass);	/*read db_password*/
    check_config_value_missing("db.password", db_pass);

    db.lookupValue("database", db_name);	/*read db_database*/
    check_config_value_missing("db.database", db_name);

    db.lookupValue("port", db_port);		/*read port*/

    if(stoi(db_port) > 65535 || stoi(db_port) < 1024 || db_port.length()> 5) {
      fprintf(stderr, "Invalid config value for database port. set default value 3306.\n");
      db_port = "3306";
    }

    table.lookupValue("drop", table_drop);	/*read table_drop*/
    check_config_value_missing("table.drop", table_drop);

    table.lookupValue("catch", table_catch);	/*read table_catch*/
    check_config_value_missing("table.catch", table_catch);

    epp.lookupValue("hostname", epp_host);	/*read epp hostname*/
    check_config_value_missing("epp.hostname", epp_host);

    epp.lookupValue("port", epp_port);		/*read epp host port*/
    //check_config_value_missing("epp.port", epp_port);
    memset(tmp, 0, 10);
    sprintf(tmp, "%d", epp_port);
    check_config_value_missing("epp.port", tmp);
    epp.lookupValue("secret", epp_password);	/*read epp password*/
    check_config_value_missing("epp.secret", epp_password);

    epp.lookupValue("clid", epp_clid);		/*read epp client*/
    check_config_value_missing("epp.clid", epp_clid);

    /*additional config value*/
    log.lookupValue("level", log_level); /*log level*/

    if(strstr(log_level.c_str(), "DEBUG"))
        log_level_flags[0] = 1;
    if(strstr(log_level.c_str(), "INFO"))
        log_level_flags[1] = 1;
    if(strstr(log_level.c_str(), "WARN"))
        log_level_flags[2] = 1;
    if(strstr(log_level.c_str(), "ERROR"))
        log_level_flags[3] = 1;

    app.lookupValue("prepare_time", prepare_time);	/*send start*/

    if(prepare_time < 0.1) {
      fprintf(stderr, "Invalid config value for prepare time. set default value 60.\n");
      prepare_time = 60;
    }
    app.lookupValue("final_time", final_time);	/*send interval*/

    if(final_time >= 0.1 || final_time <= 0) {
      fprintf(stderr, "Invalid config value for final time. set default value 0.01.\n");
      final_time = 0.01;
    }



    if(log_level_flags[0] == 1) {
      LOG_INFO("Config set:");
      save_to_log_in_start("db.hostname", db_host);		/*save logs*/
      save_to_log_in_start("db.username", db_user);
      save_to_log_in_start("db.password", db_pass);
      save_to_log_in_start("db.database", db_name);
      save_to_log_in_start("db.port", db_port);
      save_to_log_in_start("table.drop", table_drop);
      save_to_log_in_start("table.catch", table_catch);
      save_to_log_in_start("epp.hostname", epp_host);
      memset(tmp, 0, 10);
      sprintf(tmp, "%d", epp_port);
      save_to_log_in_start("epp.port", tmp);
      save_to_log_in_start("epp.secret", epp_password);
      save_to_log_in_start("epp.clid", epp_clid);
      save_to_log_in_start("log.level", log_level);

      memset(tmp, 0, 10);
      sprintf(tmp, "%f", prepare_time);
      save_to_log_in_start("app.prepare_time", tmp);
      memset(tmp, 0, 10);
      sprintf(tmp, "%f", final_time);
      save_to_log_in_start("app.final_time", tmp);
    }

    return 1;
}

/***********************************************************************
 * This function is main function
 * load config file first and create thread
 * define signal processing handlers.
 * wait thread finish
 ************************************************************************/
int main(int count, char *strings[])
{
    if(count == 3 && strcmp(strings[1],"-c") == 0) {/*./main -c my.conf */
      int n = strlen(strings[2]);   /*third parameter is conf_file*/
      n=(n>250) ? 250 : n;
      strncpy(conf_file_name, strings[2], n);
    }
    else{
      sprintf(conf_file_name,"%s.cfg",strings[0]);
    }
    void *res;
    prg = strings[0];		/*save program name*/
    if(read_conf_file() == 0)				/*Load config file*/
    {
        fprintf(stderr,"Unable to find config file, tried: %s\n",conf_file_name);
        exit(1);
    }

      pthread_t hepp;			/*thread handler*/
      LOG_INFO("daemon start.");
      g_threadworking = 1;		/*thread working variable*/
      pthread_create(&hepp, NULL, &epp_thread_body, NULL);	/*create thread*/

      if (signal(SIGINT, SIGINT_handler) == SIG_ERR) {	/*register thread handler SIGINT*/
        //printf("SIGINT install error\n");
        exit(1);
      }
      if (signal(SIGHUP, SIGHUP_handler) == SIG_ERR) { /*register thread handler SIGHUP*/
        //printf("SIGHUP install error\n");
        exit(2);
      }
      if (signal(SIGQUIT, SIGKILL_handler) == SIG_ERR) { /*register thread handler SIGQUIT*/
        //printf("SIGKILL install error\n");
        exit(3);
      }

      pthread_join(hepp, &res); free(res);	/*waiting thread finish*/
      LOG_INFO("daemon quit.");			/*program ends*/

    return 0;
}

/* ---------------------------------------------------------------- */
/* FUNCTION  SIGINT_handler:                                        */
/*    SIGINT signal handler.  It only reports that a Ctrl-C has     */
/* and gracefully finish program                                   */
/* ---------------------------------------------------------------- */

void  SIGINT_handler(IN int sig)
{
    signal(sig, SIG_IGN);
    //printf("From SIGINT: just got a %d (SIGINT ^C) signal\n", sig);
    signal(sig, SIGINT_handler);
    g_threadworking = 0;
    LOG_INFO("daemon SIGHUP | SIGINT received.");
    sd_notify(0, "STOPPING=1");
}

/* ---------------------------------------------------------------- */
/* FUNCTION  SIGHUP_handler:                                       */
/*    SIGHUP signal handler.   When SIGHUP arrives, this handler  */
/* shows a message, thread finish and restart program   */
/* ---------------------------------------------------------------- */

void  SIGHUP_handler(IN int sig)
{
    signal(sig, SIG_IGN);
    //printf("From SIGHUP: just got a %d (SIGHUP ^C) signal\n", sig);
    signal(sig, SIGHUP_handler);
    g_threadworking=0;
    LOG_INFO("daemon SIGHUP | SIGINT received.");
    sd_notify(0, "RELOADING=1");
    execve(prg, (char* const*)prg, NULL);

    //exit(42);
}
/* ---------------------------------------------------------------- */
/* FUNCTION  SIGKILL_handler:                                       */
/*    SIGKILL signal handler.   When SIGKILL arrives, this handler  */
/* shows a message, removes the shared memory segment, and exits.   */
/* ---------------------------------------------------------------- */

void  SIGKILL_handler(IN int sig)
{
    signal(sig, SIG_IGN);
    //printf("From SIGKILL: just got a %d (SIGKILL ^\\) signal"
     //       " and is about to quit\n", sig);
    sd_notifyf(0, "STATUS=Exit by sigkill.");

    exit(3);
}

