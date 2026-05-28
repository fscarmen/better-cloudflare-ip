#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#ifndef WINVER
#define WINVER 0x0601
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <direct.h>
#include <io.h>
#include <sys/stat.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET bcf_socket_t;
typedef SSIZE_T bcf_ssize_t;
#define BCF_INVALID_SOCKET INVALID_SOCKET
#define BCF_CLOSE_SOCKET closesocket
#define BCF_SOCKET_ERROR WSAGetLastError()
#define bcf_mkdir(path, mode) _mkdir(path)
#define bcf_stat _stat
#define strncasecmp _strnicmp
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
typedef int bcf_socket_t;
typedef ssize_t bcf_ssize_t;
#define BCF_INVALID_SOCKET (-1)
#define BCF_CLOSE_SOCKET close
#define BCF_SOCKET_ERROR errno
#define bcf_mkdir(path, mode) mkdir((path), (mode))
#define bcf_stat stat
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_DOWNLOAD_SIZE (32u * 1024u * 1024u)

/* Built-in fallback data lets single-file release binaries start even when the
   first HTTPS data download fails on Windows or when the upstream mirror is blocked.
   The IP ranges are Cloudflare public ranges; live downloads still take priority. */
static const char FALLBACK_URL_TXT[] =
    "speed.cloudflare.com/__down?bytes=100000000\n";

static const char FALLBACK_IPS_V4_TXT[] =
    "103.21.244.0/22\n103.22.200.0/22\n103.31.4.0/22\n104.16.0.0/13\n104.24.0.0/14\n108.162.192.0/18\n131.0.72.0/22\n141.101.64.0/18\n162.158.0.0/15\n172.64.0.0/13\n173.245.48.0/20\n188.114.96.0/20\n190.93.240.0/20\n19"
    "7.234.240.0/22\n198.41.128.0/17\n";

static const char FALLBACK_IPS_V6_TXT[] =
    "2400:cb00::/32\n2606:4700::/32\n2803:f800::/32\n2405:b500::/32\n2405:8100::/32\n2a06:98c0::/29\n2c0f:f248::/32\n";

static const char FALLBACK_LOCATIONS_JSON[] =
    "[{\"iata\":\"TIA\",\"lat\":41.4146995544,\"lon\":19.7206001282,\"cca2\":\"AL\",\"region\":\"Europe\",\"city\":\"Tirana\"},{\"iata\":\"ALG\",\"lat\":36.6910018921,\"lon\":3.2154099941,\"cca2\":\"DZ\",\"region\":\"Africa\",\"city\":\"Algiers"
    "\"},{\"iata\":\"AAE\",\"lat\":36.85596,\"lon\":7.79207,\"cca2\":\"DZ\",\"region\":\"Africa\",\"city\":\"Annaba\"},{\"iata\":\"CZL\",\"lat\":36.335972,\"lon\":6.598562,\"cca2\":\"DZ\",\"region\":\"Africa\",\"city\":\"Constantine\"},{\"iata\":\"O"
    "RN\",\"lat\":35.6911,\"lon\":-0.6416,\"cca2\":\"DZ\",\"region\":\"Africa\",\"city\":\"Oran\"},{\"iata\":\"LAD\",\"lat\":-8.8583698273,\"lon\":13.2312002182,\"cca2\":\"AO\",\"region\":\"Africa\",\"city\":\"Luanda\"},{\"iata\":\"EZE\",\"lat\":-3"
    "4.8222,\"lon\":-58.5358,\"cca2\":\"AR\",\"region\":\"South America\",\"city\":\"Buenos Aires\"},{\"iata\":\"COR\",\"lat\":-31.31,\"lon\":-64.208333,\"cca2\":\"AR\",\"region\":\"South America\",\"city\":\"C\\u00f3rdoba\"},{\"iata\":\"NQN\","
    "\"lat\":-38.9490013123,\"lon\":-68.1557006836,\"cca2\":\"AR\",\"region\":\"South America\",\"city\":\"Neuquen\"},{\"iata\":\"EVN\",\"lat\":40.1473007202,\"lon\":44.3959007263,\"cca2\":\"AM\",\"region\":\"Middle East\",\"city\":\"Yereva"
    "n\"},{\"iata\":\"ADL\",\"lat\":-34.9431729,\"lon\":138.5335637,\"cca2\":\"AU\",\"region\":\"Oceania\",\"city\":\"Adelaide\"},{\"iata\":\"BNE\",\"lat\":-27.3841991425,\"lon\":153.117004394,\"cca2\":\"AU\",\"region\":\"Oceania\",\"city\":\"Br"
    "isbane\"},{\"iata\":\"CBR\",\"lat\":-35.3069000244,\"lon\":149.1950073242,\"cca2\":\"AU\",\"region\":\"Oceania\",\"city\":\"Canberra\"},{\"iata\":\"HBA\",\"lat\":-42.883209,\"lon\":147.331665,\"cca2\":\"AU\",\"region\":\"Oceania\",\"city\""
    ":\"Hobart\"},{\"iata\":\"MEL\",\"lat\":-37.6733016968,\"lon\":144.843002319,\"cca2\":\"AU\",\"region\":\"Oceania\",\"city\":\"Melbourne\"},{\"iata\":\"PER\",\"lat\":-31.9402999878,\"lon\":115.967002869,\"cca2\":\"AU\",\"region\":\"Oceani"
    "a\",\"city\":\"Perth\"},{\"iata\":\"SYD\",\"lat\":-33.9460983276,\"lon\":151.177001953,\"cca2\":\"AU\",\"region\":\"Oceania\",\"city\":\"Sydney\"},{\"iata\":\"VIE\",\"lat\":48.1102981567,\"lon\":16.5697002411,\"cca2\":\"AT\",\"region\":\"Eu"
    "rope\",\"city\":\"Vienna\"},{\"iata\":\"LLK\",\"lat\":38.7463989258,\"lon\":48.8180007935,\"cca2\":\"AZ\",\"region\":\"Middle East\",\"city\":\"Astara\"},{\"iata\":\"GYD\",\"lat\":40.4674987793,\"lon\":50.0466995239,\"cca2\":\"AZ\",\"regi"
    "on\":\"Middle East\",\"city\":\"Baku\"},{\"iata\":\"BAH\",\"lat\":26.2707996368,\"lon\":50.6335983276,\"cca2\":\"BH\",\"region\":\"Middle East\",\"city\":\"Manama\"},{\"iata\":\"CGP\",\"lat\":22.2495995,\"lon\":91.8133011,\"cca2\":\"BD\",\""
    "region\":\"Asia Pacific\",\"city\":\"Chittagong\"},{\"iata\":\"DAC\",\"lat\":23.843347,\"lon\":90.397783,\"cca2\":\"BD\",\"region\":\"Asia Pacific\",\"city\":\"Dhaka\"},{\"iata\":\"BGI\",\"lat\":13.103562,\"lon\":-59.603226,\"cca2\":\"BB\""
    ",\"region\":\"North America\",\"city\":\"Bridgetown\"},{\"iata\":\"MSQ\",\"lat\":53.9006,\"lon\":27.599,\"cca2\":\"BY\",\"region\":\"Europe\",\"city\":\"Minsk\"},{\"iata\":\"BRU\",\"lat\":50.9014015198,\"lon\":4.4844398499,\"cca2\":\"BE\",\""
    "region\":\"Europe\",\"city\":\"Brussels\"},{\"iata\":\"PBH\",\"lat\":27.4712,\"lon\":89.6339,\"cca2\":\"BT\",\"region\":\"Asia Pacific\",\"city\":\"Thimphu\"},{\"iata\":\"LPB\",\"lat\":-16.4897,\"lon\":-68.1193,\"cca2\":\"BO\",\"region\":\"So"
    "uth America\",\"city\":\"La Paz\"},{\"iata\":\"GBE\",\"lat\":-24.6282,\"lon\":25.9231,\"cca2\":\"BW\",\"region\":\"Africa\",\"city\":\"Gaborone\"},{\"iata\":\"QWJ\",\"lat\":-22.738,\"lon\":-47.334,\"cca2\":\"BR\",\"region\":\"South America\""
    ",\"city\":\"Americana\"},{\"iata\":\"ARU\",\"lat\":-21.1413002014,\"lon\":-50.4247016907,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Aracatuba\"},{\"iata\":\"BEL\",\"lat\":-1.4563,\"lon\":-48.5013,\"cca2\":\"BR\",\"region\":\"S"
    "outh America\",\"city\":\"Bel\\u00e9m\"},{\"iata\":\"CNF\",\"lat\":-19.624444,\"lon\":-43.971944,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Belo Horizonte\"},{\"iata\":\"BNU\",\"lat\":-26.89245,\"lon\":-49.07696,\"cca2\":\"B"
    "R\",\"region\":\"South America\",\"city\":\"Blumenau\"},{\"iata\":\"BSB\",\"lat\":-15.79824,\"lon\":-47.90859,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Brasilia\"},{\"iata\":\"CFC\",\"lat\":-26.7762,\"lon\":-51.0125,\"cca2\":"
    "\"BR\",\"region\":\"South America\",\"city\":\"Cacador\"},{\"iata\":\"VCP\",\"lat\":-22.90662,\"lon\":-47.08576,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Campinas\"},{\"iata\":\"CAW\",\"lat\":-21.698299408,\"lon\":-41.301700"
    "592,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Campos dos Goytacazes\"},{\"iata\":\"XAP\",\"lat\":-27.1341991425,\"lon\":-52.6566009521,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Chapeco\"},{\"iata\":\"CGB\",\"l"
    "at\":-15.59611,\"lon\":-56.09667,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Cuiaba\"},{\"iata\":\"CWB\",\"lat\":-25.5284996033,\"lon\":-49.1758003235,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Curitiba\"},{\"ia"
    "ta\":\"FLN\",\"lat\":-27.6702785492,\"lon\":-48.5525016785,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Florianopolis\"},{\"iata\":\"FOR\",\"lat\":-3.7762799263,\"lon\":-38.5326004028,\"cca2\":\"BR\",\"region\":\"South Amer"
    "ica\",\"city\":\"Fortaleza\"},{\"iata\":\"GYN\",\"lat\":-16.69727,\"lon\":-49.26851,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Goiania\"},{\"iata\":\"JOI\",\"lat\":-26.304408,\"lon\":-48.846383,\"cca2\":\"BR\",\"region\":\"Sout"
    "h America\",\"city\":\"Joinville\"},{\"iata\":\"JDO\",\"lat\":-7.2242,\"lon\":-39.313,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Juazeiro do Norte\"},{\"iata\":\"MAO\",\"lat\":-3.11286,\"lon\":-60.01949,\"cca2\":\"BR\",\"regi"
    "on\":\"South America\",\"city\":\"Manaus\"},{\"iata\":\"PMW\",\"lat\":-10.2915000916,\"lon\":-48.3569984436,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Palmas\"},{\"iata\":\"POA\",\"lat\":-29.9944000244,\"lon\":-51.17139816"
    "28,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Porto Alegre\"},{\"iata\":\"REC\",\"lat\":-8.1264896393,\"lon\":-34.9235992432,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Recife\"},{\"iata\":\"RAO\",\"lat\":-21.1363"
    "887787,\"lon\":-47.7766685486,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Ribeirao Preto\"},{\"iata\":\"GIG\",\"lat\":-22.8099994659,\"lon\":-43.2505569458,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Rio de Ja"
    "neiro\"},{\"iata\":\"SSA\",\"lat\":-12.9086112976,\"lon\":-38.3224983215,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Salvador\"},{\"iata\":\"SJP\",\"lat\":-20.807157,\"lon\":-49.378994,\"cca2\":\"BR\",\"region\":\"South Amer"
    "ica\",\"city\":\"S\\u00e3o Jos\\u00e9 do Rio Preto\"},{\"iata\":\"SJK\",\"lat\":-23.1791,\"lon\":-45.8872,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"S\\u00e3o Jos\\u00e9 dos Campos\"},{\"iata\":\"GRU\",\"lat\":-23.43555641"
    "17,\"lon\":-46.4730567932,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"S\\u00e3o Paulo\"},{\"iata\":\"SOD\",\"lat\":-23.54389,\"lon\":-46.63445,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Sorocaba\"},{\"iata\":\"NVT"
    "\",\"lat\":-26.8251,\"lon\":-49.2695,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Timbo\"},{\"iata\":\"UDI\",\"lat\":-18.8836116791,\"lon\":-48.225276947,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Uberlandia\"},{\""
    "iata\":\"VIX\",\"lat\":-20.64871,\"lon\":-41.90857,\"cca2\":\"BR\",\"region\":\"South America\",\"city\":\"Vitoria\"},{\"iata\":\"BWN\",\"lat\":4.903052,\"lon\":114.939819,\"cca2\":\"BN\",\"region\":\"Asia Pacific\",\"city\":\"Bandar Seri"
    " Begawan\"},{\"iata\":\"SOF\",\"lat\":42.6966934204,\"lon\":23.4114360809,\"cca2\":\"BG\",\"region\":\"Europe\",\"city\":\"Sofia\"},{\"iata\":\"OUA\",\"lat\":12.3531999588,\"lon\":-1.5124200583,\"cca2\":\"BF\",\"region\":\"Africa\",\"city"
    "\":\"Ouagadougou\"},{\"iata\":\"PNH\",\"lat\":11.5466003418,\"lon\":104.84400177,\"cca2\":\"KH\",\"region\":\"Asia Pacific\",\"city\":\"Phnom Penh\"},{\"iata\":\"YYC\",\"lat\":51.113899231,\"lon\":-114.019996643,\"cca2\":\"CA\",\"region"
    "\":\"North America\",\"city\":\"Calgary\"},{\"iata\":\"YVR\",\"lat\":49.193901062,\"lon\":-123.183998108,\"cca2\":\"CA\",\"region\":\"North America\",\"city\":\"Vancouver\"},{\"iata\":\"YWG\",\"lat\":49.9099998474,\"lon\":-97.239898681"
    "6,\"cca2\":\"CA\",\"region\":\"North America\",\"city\":\"Winnipeg\"},{\"iata\":\"YHZ\",\"lat\":44.64601,\"lon\":-63.66844,\"cca2\":\"CA\",\"region\":\"North America\",\"city\":\"Halifax\"},{\"iata\":\"YOW\",\"lat\":45.3224983215,\"lon\":-7"
    "5.6691970825,\"cca2\":\"CA\",\"region\":\"North America\",\"city\":\"Ottawa\"},{\"iata\":\"YYZ\",\"lat\":43.6772003174,\"lon\":-79.6305999756,\"cca2\":\"CA\",\"region\":\"North America\",\"city\":\"Toronto\"},{\"iata\":\"YUL\",\"lat\":45."
    "4706001282,\"lon\":-73.7407989502,\"cca2\":\"CA\",\"region\":\"North America\",\"city\":\"Montr\\u00e9al\"},{\"iata\":\"YXE\",\"lat\":52.1707992554,\"lon\":-106.699996948,\"cca2\":\"CA\",\"region\":\"North America\",\"city\":\"Saskato"
    "on\"},{\"iata\":\"ARI\",\"lat\":-18.348611,\"lon\":-70.338889,\"cca2\":\"CL\",\"region\":\"South America\",\"city\":\"Arica\"},{\"iata\":\"CCP\",\"lat\":-36.8201,\"lon\":-73.0444,\"cca2\":\"CL\",\"region\":\"South America\",\"city\":\"Conce"
    "pci\\u00f3n\"},{\"iata\":\"SCL\",\"lat\":-33.3930015564,\"lon\":-70.7857971191,\"cca2\":\"CL\",\"region\":\"South America\",\"city\":\"Santiago\"},{\"iata\":\"BAQ\",\"lat\":10.8896,\"lon\":-74.7808,\"cca2\":\"CO\",\"region\":\"South Amer"
    "ica\",\"city\":\"Barranquilla\"},{\"iata\":\"BOG\",\"lat\":4.70159,\"lon\":-74.1469,\"cca2\":\"CO\",\"region\":\"South America\",\"city\":\"Bogota\"},{\"iata\":\"CLO\",\"lat\":3.54322,\"lon\":-76.3816,\"cca2\":\"CO\",\"region\":\"South Amer"
    "ica\",\"city\":\"Cali\"},{\"iata\":\"MDE\",\"lat\":6.16454,\"lon\":-75.4231,\"cca2\":\"CO\",\"region\":\"South America\",\"city\":\"Medell\\u00edn\"},{\"iata\":\"FIH\",\"lat\":-4.3857498169,\"lon\":15.4446001053,\"cca2\":\"CD\",\"region\":\""
    "Africa\",\"city\":\"Kinshasa\"},{\"iata\":\"SJO\",\"lat\":9.9938602448,\"lon\":-84.2088012695,\"cca2\":\"CR\",\"region\":\"South America\",\"city\":\"San Jos\\u00e9\"},{\"iata\":\"ABJ\",\"lat\":5.292598,\"lon\":-3.999133,\"cca2\":\"CI\",\""
    "region\":\"Africa\",\"city\":\"Abidjan\"},{\"iata\":\"ASK\",\"lat\":6.842178,\"lon\":-5.259932,\"cca2\":\"CI\",\"region\":\"Africa\",\"city\":\"Yamoussoukro\"},{\"iata\":\"ZAG\",\"lat\":45.7429008484,\"lon\":16.0687999725,\"cca2\":\"HR\",\""
    "region\":\"Europe\",\"city\":\"Zagreb\"},{\"iata\":\"LCA\",\"lat\":34.8750991821,\"lon\":33.6249008179,\"cca2\":\"CY\",\"region\":\"Europe\",\"city\":\"Nicosia\"},{\"iata\":\"PRG\",\"lat\":50.1007995605,\"lon\":14.2600002289,\"cca2\":\"CZ"
    "\",\"region\":\"Europe\",\"city\":\"Prague\"},{\"iata\":\"CPH\",\"lat\":55.6179008484,\"lon\":12.6560001373,\"cca2\":\"DK\",\"region\":\"Europe\",\"city\":\"Copenhagen\"},{\"iata\":\"JIB\",\"lat\":11.5473003387,\"lon\":43.1595001221,\"cca"
    "2\":\"DJ\",\"region\":\"Africa\",\"city\":\"Djibouti\"},{\"iata\":\"STI\",\"lat\":19.4060993195,\"lon\":-70.6046981812,\"cca2\":\"DO\",\"region\":\"North America\",\"city\":\"Santiago de los Caballeros\"},{\"iata\":\"SDQ\",\"lat\":18.429"
    "7008514,\"lon\":-69.6688995361,\"cca2\":\"DO\",\"region\":\"North America\",\"city\":\"Santo Domingo\"},{\"iata\":\"GYE\",\"lat\":-2.1894,\"lon\":-79.8891,\"cca2\":\"EC\",\"region\":\"South America\",\"city\":\"Guayaquil\"},{\"iata\":\"U"
    "IO\",\"lat\":-0.1291666667,\"lon\":-78.3575,\"cca2\":\"EC\",\"region\":\"South America\",\"city\":\"Quito\"},{\"iata\":\"CAI\",\"lat\":30.1219005585,\"lon\":31.4055995941,\"cca2\":\"EG\",\"region\":\"Africa\",\"city\":\"Cairo\"},{\"iata\":"
    "\"TLL\",\"lat\":59.4132995605,\"lon\":24.8327999115,\"cca2\":\"EE\",\"region\":\"Europe\",\"city\":\"Tallinn\"},{\"iata\":\"ADD\",\"lat\":9.00005,\"lon\":38.78446,\"cca2\":\"ET\",\"region\":\"Africa\",\"city\":\"Addis Ababa\"},{\"iata\":\"SU"
    "V\",\"lat\":-18.11319,\"lon\":178.43859,\"cca2\":\"FJ\",\"region\":\"Oceania\",\"city\":\"Suva\"},{\"iata\":\"HEL\",\"lat\":60.317199707,\"lon\":24.963300705,\"cca2\":\"FI\",\"region\":\"Europe\",\"city\":\"Helsinki\"},{\"iata\":\"BOD\",\"lat"
    "\":44.82946,\"lon\":-0.58355,\"cca2\":\"FR\",\"region\":\"Europe\",\"city\":\"Bordeaux\"},{\"iata\":\"LYS\",\"lat\":45.7263,\"lon\":5.0908,\"cca2\":\"FR\",\"region\":\"Europe\",\"city\":\"Lyon\"},{\"iata\":\"MRS\",\"lat\":43.439271922,\"lon\":"
    "5.2214241028,\"cca2\":\"FR\",\"region\":\"Europe\",\"city\":\"Marseille\"},{\"iata\":\"CDG\",\"lat\":49.0127983093,\"lon\":2.5499999523,\"cca2\":\"FR\",\"region\":\"Europe\",\"city\":\"Paris\"},{\"iata\":\"PPT\",\"lat\":-17.5536994934,\"lo"
    "n\":-149.606994629,\"cca2\":\"PF\",\"region\":\"Oceania\",\"city\":\"Tahiti\"},{\"iata\":\"TBS\",\"lat\":41.6692008972,\"lon\":44.95470047,\"cca2\":\"GE\",\"region\":\"Europe\",\"city\":\"Tbilisi\"},{\"iata\":\"TXL\",\"lat\":52.5597000122,"
    "\"lon\":13.2876996994,\"cca2\":\"DE\",\"region\":\"Europe\",\"city\":\"Berlin\"},{\"iata\":\"DUS\",\"lat\":51.2895011902,\"lon\":6.7667798996,\"cca2\":\"DE\",\"region\":\"Europe\",\"city\":\"D\\u00fcsseldorf\"},{\"iata\":\"FRA\",\"lat\":50.0"
    "264015198,\"lon\":8.543129921,\"cca2\":\"DE\",\"region\":\"Europe\",\"city\":\"Frankfurt\"},{\"iata\":\"HAM\",\"lat\":53.6304016113,\"lon\":9.9882297516,\"cca2\":\"DE\",\"region\":\"Europe\",\"city\":\"Hamburg\"},{\"iata\":\"MUC\",\"lat\":4"
    "8.3538017273,\"lon\":11.7861003876,\"cca2\":\"DE\",\"region\":\"Europe\",\"city\":\"Munich\"},{\"iata\":\"STR\",\"lat\":48.783333,\"lon\":9.183333,\"cca2\":\"DE\",\"region\":\"Europe\",\"city\":\"Stuttgart\"},{\"iata\":\"ACC\",\"lat\":5.614"
    "818,\"lon\":-0.205874,\"cca2\":\"GH\",\"region\":\"Africa\",\"city\":\"Accra\"},{\"iata\":\"ATH\",\"lat\":37.9364013672,\"lon\":23.9444999695,\"cca2\":\"GR\",\"region\":\"Europe\",\"city\":\"Athens\"},{\"iata\":\"SKG\",\"lat\":40.5196990967"
    ",\"lon\":22.9708995819,\"cca2\":\"GR\",\"region\":\"Europe\",\"city\":\"Thessaloniki\"},{\"iata\":\"GND\",\"lat\":12.007116,\"lon\":-61.7882288,\"cca2\":\"GD\",\"region\":\"South America\",\"city\":\"St. George's\"},{\"iata\":\"GUM\",\"lat"
    "\":13.4834003448,\"lon\":144.796005249,\"cca2\":\"GU\",\"region\":\"Asia Pacific\",\"city\":\"Hagatna\"},{\"iata\":\"GUA\",\"lat\":14.5832996368,\"lon\":-90.5274963379,\"cca2\":\"GT\",\"region\":\"North America\",\"city\":\"Guatemala "
    "City\"},{\"iata\":\"GEO\",\"lat\":6.825648,\"lon\":-58.163756,\"cca2\":\"GY\",\"region\":\"South America\",\"city\":\"Georgetown\"},{\"iata\":\"SAP\",\"lat\":15.4525995255,\"lon\":-87.9235992432,\"cca2\":\"HN\",\"region\":\"South Americ"
    "a\",\"city\":\"San Pedro Sula\"},{\"iata\":\"TGU\",\"lat\":14.0608,\"lon\":-87.2172,\"cca2\":\"HN\",\"region\":\"South America\",\"city\":\"Tegucigalpa\"},{\"iata\":\"HKG\",\"lat\":22.3089008331,\"lon\":113.915000916,\"cca2\":\"HK\",\"reg"
    "ion\":\"Asia Pacific\",\"city\":\"Hong Kong\"},{\"iata\":\"BUD\",\"lat\":47.4369010925,\"lon\":19.2555999756,\"cca2\":\"HU\",\"region\":\"Europe\",\"city\":\"Budapest\"},{\"iata\":\"KEF\",\"lat\":63.9850006104,\"lon\":-22.6056003571,\"c"
    "ca2\":\"IS\",\"region\":\"Europe\",\"city\":\"Reykjav\\u00edk\"},{\"iata\":\"AMD\",\"lat\":23.0225,\"lon\":72.5714,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Ahmedabad\"},{\"iata\":\"BLR\",\"lat\":13.7835719,\"lon\":76.6165937,\""
    "cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Bangalore\"},{\"iata\":\"IXC\",\"lat\":30.673500061,\"lon\":76.7884979248,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Chandigarh\"},{\"iata\":\"MAA\",\"lat\":12.9900054932,\""
    "lon\":80.1692962646,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Chennai\"},{\"iata\":\"HYD\",\"lat\":17.2313175201,\"lon\":78.4298553467,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Hyderabad\"},{\"iata\":\"CNN\",\"la"
    "t\":11.915858,\"lon\":75.55094,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Kannur\"},{\"iata\":\"KNU\",\"lat\":26.4499,\"lon\":80.3319,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Kanpur\"},{\"iata\":\"COK\",\"lat\":9.93"
    "12,\"lon\":76.2673,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Kochi\"},{\"iata\":\"CCU\",\"lat\":22.6476933,\"lon\":88.4349249,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Kolkata\"},{\"iata\":\"BOM\",\"lat\":19.088699"
    "3408,\"lon\":72.8678970337,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Mumbai\"},{\"iata\":\"NAG\",\"lat\":21.1610714,\"lon\":79.0024702,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Nagpur\"},{\"iata\":\"DEL\",\"lat\":2"
    "8.5664997101,\"lon\":77.1031036377,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"New Delhi\"},{\"iata\":\"PAT\",\"lat\":25.591299057,\"lon\":85.0879974365,\"cca2\":\"IN\",\"region\":\"Asia Pacific\",\"city\":\"Patna\"},{\"iata"
    "\":\"DPS\",\"lat\":-8.748169899,\"lon\":115.1669998169,\"cca2\":\"ID\",\"region\":\"Asia Pacific\",\"city\":\"Denpasar\"},{\"iata\":\"CGK\",\"lat\":-6.1275229,\"lon\":106.6515118,\"cca2\":\"ID\",\"region\":\"Asia Pacific\",\"city\":\"Jaka"
    "rta\"},{\"iata\":\"MLG\",\"lat\":-8.100347,\"lon\":112.186641,\"cca2\":\"ID\",\"region\":\"Asia Pacific\",\"city\":\"Malang\"},{\"iata\":\"JOG\",\"lat\":-7.7881798744,\"lon\":110.4319992065,\"cca2\":\"ID\",\"region\":\"Asia Pacific\",\"ci"
    "ty\":\"Yogyakarta\"},{\"iata\":\"BGW\",\"lat\":33.2625007629,\"lon\":44.2346000671,\"cca2\":\"IQ\",\"region\":\"Middle East\",\"city\":\"Baghdad\"},{\"iata\":\"BSR\",\"lat\":30.5491008759,\"lon\":47.6621017456,\"cca2\":\"IQ\",\"region\":"
    "\"Middle East\",\"city\":\"Basra\"},{\"iata\":\"EBL\",\"lat\":36.1901,\"lon\":43.993,\"cca2\":\"IQ\",\"region\":\"Middle East\",\"city\":\"Erbil\"},{\"iata\":\"NJF\",\"lat\":31.989722,\"lon\":44.404167,\"cca2\":\"IQ\",\"region\":\"Middle Eas"
    "t\",\"city\":\"Najaf\"},{\"iata\":\"XNH\",\"lat\":30.9358005524,\"lon\":46.0900993347,\"cca2\":\"IQ\",\"region\":\"Middle East\",\"city\":\"Nasiriyah\"},{\"iata\":\"ISU\",\"lat\":35.5668,\"lon\":45.4161,\"cca2\":\"IQ\",\"region\":\"Middle E"
    "ast\",\"city\":\"Sulaymaniyah\"},{\"iata\":\"DUB\",\"lat\":53.4212989807,\"lon\":-6.270070076,\"cca2\":\"IE\",\"region\":\"Europe\",\"city\":\"Dublin\"},{\"iata\":\"HFA\",\"lat\":32.78492,\"lon\":34.96069,\"cca2\":\"IL\",\"region\":\"Middle"
    " East\",\"city\":\"Haifa\"},{\"iata\":\"TLV\",\"lat\":32.0113983154,\"lon\":34.8866996765,\"cca2\":\"IL\",\"region\":\"Middle East\",\"city\":\"Tel Aviv\"},{\"iata\":\"MXP\",\"lat\":45.6305999756,\"lon\":8.7281103134,\"cca2\":\"IT\",\"reg"
    "ion\":\"Europe\",\"city\":\"Milan\"},{\"iata\":\"PMO\",\"lat\":38.16114,\"lon\":13.31546,\"cca2\":\"IT\",\"region\":\"Europe\",\"city\":\"Palermo\"},{\"iata\":\"FCO\",\"lat\":41.8045005798,\"lon\":12.2508001328,\"cca2\":\"IT\",\"region\":\"Eu"
    "rope\",\"city\":\"Rome\"},{\"iata\":\"KIN\",\"lat\":17.9951,\"lon\":-76.7846,\"cca2\":\"JM\",\"region\":\"North America\",\"city\":\"Kingston\"},{\"iata\":\"FUK\",\"lat\":33.5902,\"lon\":130.4017,\"cca2\":\"JP\",\"region\":\"Asia Pacific\",\""
    "city\":\"Fukuoka\"},{\"iata\":\"OKA\",\"lat\":26.1958,\"lon\":127.646,\"cca2\":\"JP\",\"region\":\"Asia Pacific\",\"city\":\"Naha\"},{\"iata\":\"KIX\",\"lat\":34.4272994995,\"lon\":135.244003296,\"cca2\":\"JP\",\"region\":\"Asia Pacific\","
    "\"city\":\"Osaka\"},{\"iata\":\"NRT\",\"lat\":35.7647018433,\"lon\":140.386001587,\"cca2\":\"JP\",\"region\":\"Asia Pacific\",\"city\":\"Tokyo\"},{\"iata\":\"AMM\",\"lat\":31.7226009369,\"lon\":35.9931983948,\"cca2\":\"JO\",\"region\":\"Mi"
    "ddle East\",\"city\":\"Amman\"},{\"iata\":\"AKX\",\"lat\":50.286922,\"lon\":57.224121,\"cca2\":\"KZ\",\"region\":\"Europe\",\"city\":\"Aktobe\"},{\"iata\":\"ALA\",\"lat\":43.3521003723,\"lon\":77.0404968262,\"cca2\":\"KZ\",\"region\":\"Euro"
    "pe\",\"city\":\"Almaty\"},{\"iata\":\"NQZ\",\"lat\":51.167801,\"lon\":71.418893,\"cca2\":\"KZ\",\"region\":\"Europe\",\"city\":\"Astana\"},{\"iata\":\"MBA\",\"lat\":-4.0348300934,\"lon\":39.5942001343,\"cca2\":\"KE\",\"region\":\"Africa\",\"c"
    "ity\":\"Mombasa\"},{\"iata\":\"NBO\",\"lat\":-1.319239974,\"lon\":36.9277992249,\"cca2\":\"KE\",\"region\":\"Africa\",\"city\":\"Nairobi\"},{\"iata\":\"ICN\",\"lat\":37.4691009521,\"lon\":126.450996399,\"cca2\":\"KR\",\"region\":\"Asia Pa"
    "cific\",\"city\":\"Seoul\"},{\"iata\":\"KWI\",\"lat\":29.226600647,\"lon\":47.9688987732,\"cca2\":\"KW\",\"region\":\"Middle East\",\"city\":\"Kuwait City\"},{\"iata\":\"FRU\",\"lat\":42.875608,\"lon\":74.604613,\"cca2\":\"KG\",\"region\":"
    "\"Asia Pacific\",\"city\":\"Bishkek\"},{\"iata\":\"VTE\",\"lat\":17.9757,\"lon\":102.5683,\"cca2\":\"LA\",\"region\":\"Asia Pacific\",\"city\":\"Vientiane\"},{\"iata\":\"RIX\",\"lat\":56.9235992432,\"lon\":23.9710998535,\"cca2\":\"LV\",\"r"
    "egion\":\"Europe\",\"city\":\"Riga\"},{\"iata\":\"BEY\",\"lat\":33.8208999634,\"lon\":35.4883995056,\"cca2\":\"LB\",\"region\":\"Middle East\",\"city\":\"Beirut\"},{\"iata\":\"VNO\",\"lat\":54.6341018677,\"lon\":25.2858009338,\"cca2\":\"L"
    "T\",\"region\":\"Europe\",\"city\":\"Vilnius\"},{\"iata\":\"LUX\",\"lat\":49.6265983582,\"lon\":6.211520195,\"cca2\":\"LU\",\"region\":\"Europe\",\"city\":\"Luxembourg City\"},{\"iata\":\"MFM\",\"lat\":22.1495990753,\"lon\":113.592002869"
    ",\"cca2\":\"MO\",\"region\":\"Asia Pacific\",\"city\":\"Macau\"},{\"iata\":\"TNR\",\"lat\":-18.91368,\"lon\":47.53613,\"cca2\":\"MG\",\"region\":\"Africa\",\"city\":\"Antananarivo\"},{\"iata\":\"LLW\",\"lat\":-13.980935,\"lon\":33.761462,\"c"
    "ca2\":\"MW\",\"region\":\"Africa\",\"city\":\"Lilongwe\"},{\"iata\":\"JHB\",\"lat\":1.635848,\"lon\":103.665943,\"cca2\":\"MY\",\"region\":\"Asia Pacific\",\"city\":\"Johor Bahru\"},{\"iata\":\"KUL\",\"lat\":2.745579958,\"lon\":101.7099990"
    "84,\"cca2\":\"MY\",\"region\":\"Asia Pacific\",\"city\":\"Kuala Lumpur\"},{\"iata\":\"KCH\",\"lat\":1.709727,\"lon\":110.353455,\"cca2\":\"MY\",\"region\":\"Asia Pacific\",\"city\":\"Kuching\"},{\"iata\":\"MLE\",\"lat\":4.1748,\"lon\":73.50"
    "888,\"cca2\":\"MV\",\"region\":\"Asia Pacific\",\"city\":\"Male\"},{\"iata\":\"MLA\",\"lat\":35.886054,\"lon\":14.47609,\"cca2\":\"MT\",\"region\":\"Europe\",\"city\":\"Santa Venera\"},{\"iata\":\"MRU\",\"lat\":-20.4302005768,\"lon\":57.683"
    "6013794,\"cca2\":\"MU\",\"region\":\"Africa\",\"city\":\"Port Louis\"},{\"iata\":\"GDL\",\"lat\":20.5217990875,\"lon\":-103.3109970093,\"cca2\":\"MX\",\"region\":\"North America\",\"city\":\"Guadalajara\"},{\"iata\":\"MEX\",\"lat\":19.436"
    "3002777,\"lon\":-99.0720977783,\"cca2\":\"MX\",\"region\":\"North America\",\"city\":\"Mexico City\"},{\"iata\":\"QRO\",\"lat\":20.6173000336,\"lon\":-100.185997009,\"cca2\":\"MX\",\"region\":\"North America\",\"city\":\"Queretaro\"},"
    "{\"iata\":\"KIV\",\"lat\":46.9277000427,\"lon\":28.9309997559,\"cca2\":\"MD\",\"region\":\"Europe\",\"city\":\"Chi\\u0219in\\u0103u\"},{\"iata\":\"ULN\",\"lat\":47.8431015015,\"lon\":106.766998291,\"cca2\":\"MN\",\"region\":\"Asia Pacifi"
    "c\",\"city\":\"Ulaanbaatar\"},{\"iata\":\"MPM\",\"lat\":-25.9207992554,\"lon\":32.5726013184,\"cca2\":\"MZ\",\"region\":\"Africa\",\"city\":\"Maputo\"},{\"iata\":\"WDH\",\"lat\":-22.565587,\"lon\":17.085334,\"cca2\":\"NA\",\"region\":\"Afri"
    "ca\",\"city\":\"Windhoek\"},{\"iata\":\"KTM\",\"lat\":27.6965999603,\"lon\":85.3591003418,\"cca2\":\"NP\",\"region\":\"Asia Pacific\",\"city\":\"Kathmandu\"},{\"iata\":\"AMS\",\"lat\":52.3086013794,\"lon\":4.7638897896,\"cca2\":\"NL\",\"r"
    "egion\":\"Europe\",\"city\":\"Amsterdam\"},{\"iata\":\"NOU\",\"lat\":-22.0146007538,\"lon\":166.212997436,\"cca2\":\"NC\",\"region\":\"Oceania\",\"city\":\"Noumea\"},{\"iata\":\"AKL\",\"lat\":-37.0080986023,\"lon\":174.792007446,\"cca2\""
    ":\"NZ\",\"region\":\"Oceania\",\"city\":\"Auckland\"},{\"iata\":\"CHC\",\"lat\":-43.4893989563,\"lon\":172.5319976807,\"cca2\":\"NZ\",\"region\":\"Oceania\",\"city\":\"Christchurch\"},{\"iata\":\"LOS\",\"lat\":6.5773701668,\"lon\":3.32116"
    "0078,\"cca2\":\"NG\",\"region\":\"Africa\",\"city\":\"Lagos\"},{\"iata\":\"SKP\",\"lat\":41.9616012573,\"lon\":21.6214008331,\"cca2\":\"MK\",\"region\":\"Europe\",\"city\":\"Skopje\"},{\"iata\":\"OSL\",\"lat\":60.193901062,\"lon\":11.100399"
    "971,\"cca2\":\"NO\",\"region\":\"Europe\",\"city\":\"Oslo\"},{\"iata\":\"MCT\",\"lat\":23.5932998657,\"lon\":58.2844009399,\"cca2\":\"OM\",\"region\":\"Middle East\",\"city\":\"Muscat\"},{\"iata\":\"ISB\",\"lat\":33.6166992188,\"lon\":73.09"
    "91973877,\"cca2\":\"PK\",\"region\":\"Asia Pacific\",\"city\":\"Islamabad\"},{\"iata\":\"KHI\",\"lat\":24.9064998627,\"lon\":67.1607971191,\"cca2\":\"PK\",\"region\":\"Asia Pacific\",\"city\":\"Karachi\"},{\"iata\":\"LHE\",\"lat\":31.5216"
    "007233,\"lon\":74.4036026001,\"cca2\":\"PK\",\"region\":\"Asia Pacific\",\"city\":\"Lahore\"},{\"iata\":\"ZDM\",\"lat\":32.2719,\"lon\":35.0194,\"cca2\":\"PS\",\"region\":\"Middle East\",\"city\":\"Ramallah\"},{\"iata\":\"PTY\",\"lat\":9.07"
    "13596344,\"lon\":-79.3834991455,\"cca2\":\"PA\",\"region\":\"South America\",\"city\":\"Panama City\"},{\"iata\":\"ASU\",\"lat\":-25.2399997711,\"lon\":-57.5200004578,\"cca2\":\"PY\",\"region\":\"South America\",\"city\":\"Asunci\\u00"
    "f3n\"},{\"iata\":\"LIM\",\"lat\":-12.021900177,\"lon\":-77.1143035889,\"cca2\":\"PE\",\"region\":\"South America\",\"city\":\"Lima\"},{\"iata\":\"CGY\",\"lat\":8.4156198502,\"lon\":124.611000061,\"cca2\":\"PH\",\"region\":\"Asia Pacific"
    "\",\"city\":\"Cagayan de Oro\"},{\"iata\":\"CEB\",\"lat\":10.3074998856,\"lon\":123.978996277,\"cca2\":\"PH\",\"region\":\"Asia Pacific\",\"city\":\"Cebu\"},{\"iata\":\"MNL\",\"lat\":14.508600235,\"lon\":121.019996643,\"cca2\":\"PH\",\"re"
    "gion\":\"Asia Pacific\",\"city\":\"Manila\"},{\"iata\":\"CRK\",\"lat\":15.1859,\"lon\":120.5599,\"cca2\":\"PH\",\"region\":\"Asia Pacific\",\"city\":\"Tarlac City\"},{\"iata\":\"WAW\",\"lat\":52.1656990051,\"lon\":20.9671001434,\"cca2\":"
    "\"PL\",\"region\":\"Europe\",\"city\":\"Warsaw\"},{\"iata\":\"WRO\",\"lat\":51.106742,\"lon\":16.983773,\"cca2\":\"PL\",\"region\":\"Europe\",\"city\":\"Wroclaw\"},{\"iata\":\"LIS\",\"lat\":38.7812995911,\"lon\":-9.1359195709,\"cca2\":\"PT\","
    "\"region\":\"Europe\",\"city\":\"Lisbon\"},{\"iata\":\"SJU\",\"lat\":18.411391,\"lon\":-66.102793,\"cca2\":\"PR\",\"region\":\"North America\",\"city\":\"San Juan\"},{\"iata\":\"DOH\",\"lat\":25.2605946,\"lon\":51.6137665,\"cca2\":\"QA\",\"r"
    "egion\":\"Middle East\",\"city\":\"Doha\"},{\"iata\":\"RUN\",\"lat\":-20.8871002197,\"lon\":55.5102996826,\"cca2\":\"RE\",\"region\":\"Africa\",\"city\":\"Saint-Denis\"},{\"iata\":\"OTP\",\"lat\":44.5722007751,\"lon\":26.1021995544,\"cc"
    "a2\":\"RO\",\"region\":\"Europe\",\"city\":\"Bucharest\"},{\"iata\":\"KJA\",\"lat\":56.0153,\"lon\":92.8932,\"cca2\":\"RU\",\"region\":\"Asia Pacific\",\"city\":\"Krasnoyarsk\"},{\"iata\":\"DME\",\"lat\":55.4087982178,\"lon\":37.9062995911"
    ",\"cca2\":\"RU\",\"region\":\"Europe\",\"city\":\"Moscow\"},{\"iata\":\"LED\",\"lat\":59.8003005981,\"lon\":30.2625007629,\"cca2\":\"RU\",\"region\":\"Europe\",\"city\":\"Saint Petersburg\"},{\"iata\":\"KGL\",\"lat\":-1.9686299563,\"lon\":3"
    "0.1394996643,\"cca2\":\"RW\",\"region\":\"Africa\",\"city\":\"Kigali\"},{\"iata\":\"DMM\",\"lat\":26.471200943,\"lon\":49.7979011536,\"cca2\":\"SA\",\"region\":\"Middle East\",\"city\":\"Dammam\"},{\"iata\":\"JED\",\"lat\":21.679599762,\"l"
    "on\":39.15650177,\"cca2\":\"SA\",\"region\":\"Middle East\",\"city\":\"Jeddah\"},{\"iata\":\"RUH\",\"lat\":24.9575996399,\"lon\":46.6987991333,\"cca2\":\"SA\",\"region\":\"Middle East\",\"city\":\"Riyadh\"},{\"iata\":\"DKR\",\"lat\":14.741"
    "2099,\"lon\":-17.4889771,\"cca2\":\"SN\",\"region\":\"Africa\",\"city\":\"Dakar\"},{\"iata\":\"BEG\",\"lat\":44.8184013367,\"lon\":20.3090991974,\"cca2\":\"RS\",\"region\":\"Europe\",\"city\":\"Belgrade\"},{\"iata\":\"SIN\",\"lat\":1.350190"
    "0434,\"lon\":103.994003296,\"cca2\":\"SG\",\"region\":\"Asia Pacific\",\"city\":\"Singapore\"},{\"iata\":\"BTS\",\"lat\":48.1486,\"lon\":17.1077,\"cca2\":\"SK\",\"region\":\"Europe\",\"city\":\"Bratislava\"},{\"iata\":\"CPT\",\"lat\":-33.96"
    "48017883,\"lon\":18.6016998291,\"cca2\":\"ZA\",\"region\":\"Africa\",\"city\":\"Cape Town\"},{\"iata\":\"DUR\",\"lat\":-29.6144444444,\"lon\":31.1197222222,\"cca2\":\"ZA\",\"region\":\"Africa\",\"city\":\"Durban\"},{\"iata\":\"JNB\",\"lat\""
    ":-26.133333,\"lon\":28.25,\"cca2\":\"ZA\",\"region\":\"Africa\",\"city\":\"Johannesburg\"},{\"iata\":\"BCN\",\"lat\":41.2971000671,\"lon\":2.0784599781,\"cca2\":\"ES\",\"region\":\"Europe\",\"city\":\"Barcelona\"},{\"iata\":\"MAD\",\"lat\":"
    "40.4936,\"lon\":-3.56676,\"cca2\":\"ES\",\"region\":\"Europe\",\"city\":\"Madrid\"},{\"iata\":\"CMB\",\"lat\":7.1807599068,\"lon\":79.8841018677,\"cca2\":\"LK\",\"region\":\"Asia Pacific\",\"city\":\"Colombo\"},{\"iata\":\"PBM\",\"lat\":5.4"
    "52831,\"lon\":-55.187783,\"cca2\":\"SR\",\"region\":\"South America\",\"city\":\"Paramaribo\"},{\"iata\":\"GOT\",\"lat\":57.6627998352,\"lon\":12.279800415,\"cca2\":\"SE\",\"region\":\"Europe\",\"city\":\"Gothenburg\"},{\"iata\":\"ARN\",\""
    "lat\":59.6519012451,\"lon\":17.9186000824,\"cca2\":\"SE\",\"region\":\"Europe\",\"city\":\"Stockholm\"},{\"iata\":\"GVA\",\"lat\":46.2380981445,\"lon\":6.1089501381,\"cca2\":\"CH\",\"region\":\"Europe\",\"city\":\"Geneva\"},{\"iata\":\"ZR"
    "H\",\"lat\":47.4646987915,\"lon\":8.5491695404,\"cca2\":\"CH\",\"region\":\"Europe\",\"city\":\"Zurich\"},{\"iata\":\"KHH\",\"lat\":22.5771007538,\"lon\":120.3499984741,\"cca2\":\"TW\",\"region\":\"Asia Pacific\",\"city\":\"Kaohsiung Ci"
    "ty\"},{\"iata\":\"TPE\",\"lat\":25.0776996613,\"lon\":121.233001709,\"cca2\":\"TW\",\"region\":\"Asia Pacific\",\"city\":\"Taipei\"},{\"iata\":\"DAR\",\"lat\":-6.8781099319,\"lon\":39.2025985718,\"cca2\":\"TZ\",\"region\":\"Africa\",\"cit"
    "y\":\"Dar es Salaam\"},{\"iata\":\"BKK\",\"lat\":13.6810998917,\"lon\":100.747001648,\"cca2\":\"TH\",\"region\":\"Asia Pacific\",\"city\":\"Bangkok\"},{\"iata\":\"CNX\",\"lat\":18.7667999268,\"lon\":98.962600708,\"cca2\":\"TH\",\"region"
    "\":\"Asia Pacific\",\"city\":\"Chiang Mai\"},{\"iata\":\"URT\",\"lat\":9.1325998306,\"lon\":99.135597229,\"cca2\":\"TH\",\"region\":\"Asia Pacific\",\"city\":\"Surat Thani\"},{\"iata\":\"POS\",\"lat\":10.5953998566,\"lon\":-61.33720016"
    "48,\"cca2\":\"TT\",\"region\":\"South America\",\"city\":\"Port of Spain\"},{\"iata\":\"TUN\",\"lat\":36.8510017395,\"lon\":10.2271995544,\"cca2\":\"TN\",\"region\":\"Africa\",\"city\":\"Tunis\"},{\"iata\":\"IST\",\"lat\":40.9768981934,\"l"
    "on\":28.8145999908,\"cca2\":\"TR\",\"region\":\"Europe\",\"city\":\"Istanbul\"},{\"iata\":\"ADB\",\"lat\":38.32377,\"lon\":27.14317,\"cca2\":\"TR\",\"region\":\"Europe\",\"city\":\"Izmir\"},{\"iata\":\"EBB\",\"lat\":0.3152,\"lon\":32.5816,\"c"
    "ca2\":\"UG\",\"region\":\"Africa\",\"city\":\"Kampala\"},{\"iata\":\"KBP\",\"lat\":50.3450012207,\"lon\":30.8946990967,\"cca2\":\"UA\",\"region\":\"Europe\",\"city\":\"Kyiv\"},{\"iata\":\"DXB\",\"lat\":25.2527999878,\"lon\":55.3643989563,\""
    "cca2\":\"AE\",\"region\":\"Middle East\",\"city\":\"Dubai\"},{\"iata\":\"LHR\",\"lat\":51.4706001282,\"lon\":-0.4619410038,\"cca2\":\"GB\",\"region\":\"Europe\",\"city\":\"London\"},{\"iata\":\"MAN\",\"lat\":53.3536987305,\"lon\":-2.274950"
    "0275,\"cca2\":\"GB\",\"region\":\"Europe\",\"city\":\"Manchester\"},{\"iata\":\"ANC\",\"lat\":61.158555,\"lon\":-149.890208,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Anchorage\"},{\"iata\":\"PHX\",\"lat\":33.434299469,\"lon\":"
    "-112.012001038,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Phoenix\"},{\"iata\":\"LAX\",\"lat\":33.94250107,\"lon\":-118.4079971,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Los Angeles\"},{\"iata\":\"SMF\",\"lat\":"
    "38.695400238,\"lon\":-121.591003418,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Sacramento\"},{\"iata\":\"SAN\",\"lat\":32.7336006165,\"lon\":-117.190002441,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"San Dieg"
    "o\"},{\"iata\":\"SFO\",\"lat\":37.6189994812,\"lon\":-122.375,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"San Francisco\"},{\"iata\":\"SJC\",\"lat\":37.3625984192,\"lon\":-121.929000855,\"cca2\":\"US\",\"region\":\"North Ame"
    "rica\",\"city\":\"San Jose\"},{\"iata\":\"DEN\",\"lat\":39.8616981506,\"lon\":-104.672996521,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Denver\"},{\"iata\":\"JAX\",\"lat\":30.4941005707,\"lon\":-81.6878967285,\"cca2\":\"US\""
    ",\"region\":\"North America\",\"city\":\"Jacksonville\"},{\"iata\":\"MIA\",\"lat\":25.7931995392,\"lon\":-80.2906036377,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Miami\"},{\"iata\":\"TLH\",\"lat\":30.3964996338,\"lon\":-84"
    ".3503036499,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Tallahassee\"},{\"iata\":\"TPA\",\"lat\":27.9755001068,\"lon\":-82.533203125,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Tampa\"},{\"iata\":\"ATL\",\"lat\":33"
    ".6366996765,\"lon\":-84.4281005859,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Atlanta\"},{\"iata\":\"HNL\",\"lat\":21.3187007904,\"lon\":-157.9219970703,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Honolulu\"},"
    "{\"iata\":\"ORD\",\"lat\":41.97859955,\"lon\":-87.90480042,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Chicago\"},{\"iata\":\"IND\",\"lat\":39.717300415,\"lon\":-86.2944030762,\"cca2\":\"US\",\"region\":\"North America\",\"ci"
    "ty\":\"Indianapolis\"},{\"iata\":\"BGR\",\"lat\":44.8081,\"lon\":-68.795,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Bangor\"},{\"iata\":\"BOS\",\"lat\":42.36429977,\"lon\":-71.00520325,\"cca2\":\"US\",\"region\":\"North Ameri"
    "ca\",\"city\":\"Boston\"},{\"iata\":\"DTW\",\"lat\":42.2123985291,\"lon\":-83.3534011841,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Detroit\"},{\"iata\":\"MSP\",\"lat\":44.8819999695,\"lon\":-93.2218017578,\"cca2\":\"US\",\"r"
    "egion\":\"North America\",\"city\":\"Minneapolis\"},{\"iata\":\"MCI\",\"lat\":39.2975997925,\"lon\":-94.7138977051,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Kansas City\"},{\"iata\":\"STL\",\"lat\":38.7486991882,\"lon\":-"
    "90.3700027466,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"St. Louis\"},{\"iata\":\"OMA\",\"lat\":41.3031997681,\"lon\":-95.8940963745,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Omaha\"},{\"iata\":\"LAS\",\"lat\":3"
    "6.08010101,\"lon\":-115.1520004,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Las Vegas\"},{\"iata\":\"EWR\",\"lat\":40.6925010681,\"lon\":-74.1687011719,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Newark\"},{\"ia"
    "ta\":\"ABQ\",\"lat\":35.0844,\"lon\":-106.6504,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Albuquerque\"},{\"iata\":\"BUF\",\"lat\":42.94049835,\"lon\":-78.73220062,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Buffa"
    "lo\"},{\"iata\":\"CLT\",\"lat\":35.2140007019,\"lon\":-80.9430999756,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Charlotte\"},{\"iata\":\"RDU\",\"lat\":35.93543,\"lon\":-78.88075,\"cca2\":\"US\",\"region\":\"North America\",\""
    "city\":\"Durham\"},{\"iata\":\"CLE\",\"lat\":41.50069,\"lon\":-81.68412,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Cleveland\"},{\"iata\":\"CMH\",\"lat\":39.9980010986,\"lon\":-82.8918991089,\"cca2\":\"US\",\"region\":\"North"
    " America\",\"city\":\"Columbus\"},{\"iata\":\"OKC\",\"lat\":35.46655,\"lon\":-97.65373,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Oklahoma City\"},{\"iata\":\"PDX\",\"lat\":45.58869934,\"lon\":-122.5979996,\"cca2\":\"US\",\"r"
    "egion\":\"North America\",\"city\":\"Portland\"},{\"iata\":\"PHL\",\"lat\":39.8718986511,\"lon\":-75.2410964966,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Philadelphia\"},{\"iata\":\"PIT\",\"lat\":40.49150085,\"lon\":-80.2"
    "3290253,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Pittsburgh\"},{\"iata\":\"FSD\",\"lat\":43.540819819502,\"lon\":-96.65511577730963,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Sioux Falls\"},{\"iata\":\"MEM\","
    "\"lat\":35.0424003601,\"lon\":-89.9766998291,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Memphis\"},{\"iata\":\"BNA\",\"lat\":36.1245002747,\"lon\":-86.6781997681,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Nash"
    "ville\"},{\"iata\":\"AUS\",\"lat\":30.1975,\"lon\":-97.6664,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Austin\"},{\"iata\":\"DFW\",\"lat\":32.8968009949,\"lon\":-97.0380020142,\"cca2\":\"US\",\"region\":\"North America\",\"ci"
    "ty\":\"Dallas\"},{\"iata\":\"IAH\",\"lat\":29.9843997955,\"lon\":-95.3414001465,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Houston\"},{\"iata\":\"SAT\",\"lat\":29.429461,\"lon\":-98.487061,\"cca2\":\"US\",\"region\":\"North A"
    "merica\",\"city\":\"San Antonio\"},{\"iata\":\"SLC\",\"lat\":40.7883987427,\"lon\":-111.977996826,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Salt Lake City\"},{\"iata\":\"IAD\",\"lat\":38.94449997,\"lon\":-77.45580292,\"c"
    "ca2\":\"US\",\"region\":\"North America\",\"city\":\"Ashburn\"},{\"iata\":\"ORF\",\"lat\":36.8945999146,\"lon\":-76.2012023926,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Norfolk\"},{\"iata\":\"RIC\",\"lat\":37.5051994324,\"lo"
    "n\":-77.3197021484,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Richmond\"},{\"iata\":\"SEA\",\"lat\":47.4490013123,\"lon\":-122.308998108,\"cca2\":\"US\",\"region\":\"North America\",\"city\":\"Seattle\"},{\"iata\":\"DAD\",\"l"
    "at\":16.02636,\"lon\":108.20869,\"cca2\":\"VN\",\"region\":\"Asia Pacific\",\"city\":\"Da Nang\"},{\"iata\":\"HAN\",\"lat\":21.221200943,\"lon\":105.806999206,\"cca2\":\"VN\",\"region\":\"Asia Pacific\",\"city\":\"Hanoi\"},{\"iata\":\"SGN"
    "\",\"lat\":10.8187999725,\"lon\":106.652000427,\"cca2\":\"VN\",\"region\":\"Asia Pacific\",\"city\":\"Ho Chi Minh City\"},{\"iata\":\"LUN\",\"lat\":-15.371446,\"lon\":28.317837,\"cca2\":\"ZM\",\"region\":\"Africa\",\"city\":\"Lusaka\"},{"
    "\"iata\":\"HRE\",\"lat\":-17.9318008423,\"lon\":31.0928001404,\"cca2\":\"ZW\",\"region\":\"Africa\",\"city\":\"Harare\"}]\n";
#define MAX_LINE_LEN      1024
#define MAX_IP_LEN        128
#define MAX_DOMAIN_LEN    256
#define MAX_FILE_LEN      1024
#define MAX_HEADER_SIZE   65536
#define LOCATION_TABLE_SIZE 4096

/* ----------------------- 通用类型 ----------------------- */

typedef struct {
    char **items;
    size_t len;
    size_t cap;
} StringList;

typedef struct {
    char ip[MAX_IP_LEN];
    int latency_ms;
} RTTResult;

typedef struct {
    RTTResult *items;
    size_t len;
    size_t cap;
} RTTVector;

typedef struct {
    char iata[16];
    char city[256];
    int used;
} LocationEntry;

typedef struct {
    int max_speed_kbps;
    int tcp_ms;
    char data_center[32];
} SpeedResult;

typedef struct {
    char ip[MAX_IP_LEN];
    int max_speed_kbps;
    int tcp_ms;
    char data_center[256];
} CloudflareResult;

/* ----------------------- 全局状态 ----------------------- */

static char data_dir[PATH_MAX] = "";
static pthread_mutex_t random_mu = PTHREAD_MUTEX_INITIALIZER;
static uint64_t random_state = 0;

static LocationEntry location_table[LOCATION_TABLE_SIZE];
static pthread_rwlock_t location_lock = PTHREAD_RWLOCK_INITIALIZER;

static char speed_test_domain[MAX_DOMAIN_LEN] = "";
static char speed_test_file[MAX_FILE_LEN] = "";

static pthread_once_t rtt_ssl_once = PTHREAD_ONCE_INIT;
static SSL_CTX *rtt_ssl_ctx = NULL;

/* ----------------------- 基础工具 ----------------------- */

static void platform_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed; network functions are unavailable.\n");
        exit(1);
    }
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}

static void platform_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}


static long long now_ms(void) {
#ifdef _WIN32
    return (long long)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
#endif
}


static void trim_in_place(char *s) {
    if (!s) return;
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
}

static int read_line_trim(char *buf, size_t size) {
    if (!fgets(buf, (int)size, stdin)) return 0;
    buf[strcspn(buf, "\r\n")] = '\0';
    trim_in_place(buf);
    return 1;
}

static void copy_cstr(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) return;
    if (!src) src = "";
    size_t n = strlen(src);
    if (n >= dst_size) n = dst_size - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void append_cstr(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0 || !src) return;
    size_t used = strlen(dst);
    if (used >= dst_size - 1) return;
    size_t n = strlen(src);
    if (n > dst_size - used - 1) n = dst_size - used - 1;
    memcpy(dst + used, src, n);
    dst[used + n] = '\0';
}

static const char *data_path(const char *name, char *out, size_t out_size) {
    if (!out || out_size == 0) return out;
    out[0] = '\0';
    if (data_dir[0] == '\0') {
        copy_cstr(out, out_size, name);
    } else {
        copy_cstr(out, out_size, data_dir);
        append_cstr(out, out_size, "/");
        append_cstr(out, out_size, name);
    }
    return out;
}

static int file_exists(const char *path) {
    struct bcf_stat st;
    return bcf_stat(path, &st) == 0;
}

static int mkdir_p(const char *dir) {
    if (!dir || dir[0] == '\0' || strcmp(dir, ".") == 0) return 0;
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp);
    if (len == 0) return 0;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (bcf_mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (bcf_mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int save_to_file(const char *filename, const char *content, size_t len) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", filename);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (mkdir_p(dir) != 0) return -1;
    }

    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;
    size_t written = fwrite(content, 1, len, fp);
    int ok = (written == len && fclose(fp) == 0);
    return ok ? 0 : -1;
}

static int save_text_to_file(const char *filename, const char *content) {
    return save_to_file(filename, content, strlen(content));
}

static char *get_file_content(const char *filename, size_t *out_len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

static void init_random(void) {
#ifdef _WIN32
    random_state = ((uint64_t)time(NULL) << 32) ^ (uint64_t)GetTickCount64() ^ (uint64_t)GetCurrentProcessId();
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    random_state = ((uint64_t)ts.tv_sec << 32) ^ (uint64_t)ts.tv_nsec ^ (uint64_t)getpid();
#endif
    if (random_state == 0) random_state = 0x9e3779b97f4a7c15ULL;
}

static uint64_t next_random_u64_locked(void) {
    /* xorshift64*: 轻量、快速，外部使用 mutex 保证与 Go 版随机源一样串行访问 */
    random_state ^= random_state >> 12;
    random_state ^= random_state << 25;
    random_state ^= random_state >> 27;
    return random_state * 2685821657736338717ULL;
}

static int next_random_intn(int n) {
    if (n <= 0) return 0;
    pthread_mutex_lock(&random_mu);
    uint64_t v = next_random_u64_locked();
    pthread_mutex_unlock(&random_mu);
    return (int)(v % (uint64_t)n);
}

/* ----------------------- 动态数组 ----------------------- */

static void string_list_init(StringList *list) {
    list->items = NULL;
    list->len = 0;
    list->cap = 0;
}

static int string_list_push_dup(StringList *list, const char *s) {
    if (list->len == list->cap) {
        size_t new_cap = list->cap ? list->cap * 2 : 32;
        char **new_items = (char **)realloc(list->items, new_cap * sizeof(char *));
        if (!new_items) return -1;
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->len] = strdup(s ? s : "");
    if (!list->items[list->len]) return -1;
    list->len++;
    return 0;
}

static void string_list_free(StringList *list) {
    if (!list) return;
    for (size_t i = 0; i < list->len; i++) free(list->items[i]);
    free(list->items);
    list->items = NULL;
    list->len = 0;
    list->cap = 0;
}

static void rtt_vector_init(RTTVector *vec) {
    vec->items = NULL;
    vec->len = 0;
    vec->cap = 0;
}

static int rtt_vector_push(RTTVector *vec, const char *ip, int latency_ms) {
    if (vec->len == vec->cap) {
        size_t new_cap = vec->cap ? vec->cap * 2 : 32;
        RTTResult *new_items = (RTTResult *)realloc(vec->items, new_cap * sizeof(RTTResult));
        if (!new_items) return -1;
        vec->items = new_items;
        vec->cap = new_cap;
    }
    snprintf(vec->items[vec->len].ip, sizeof(vec->items[vec->len].ip), "%s", ip);
    vec->items[vec->len].latency_ms = latency_ms;
    vec->len++;
    return 0;
}

static void rtt_vector_free(RTTVector *vec) {
    free(vec->items);
    vec->items = NULL;
    vec->len = 0;
    vec->cap = 0;
}

/* ----------------------- libcurl 下载 ----------------------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
    size_t max_len;
    int too_large;
} MemoryBuffer;

static size_t curl_write_to_memory(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t bytes = size * nmemb;
    MemoryBuffer *mem = (MemoryBuffer *)userdata;
    if (mem->len + bytes > mem->max_len) {
        mem->too_large = 1;
        return 0;
    }
    if (mem->len + bytes + 1 > mem->cap) {
        size_t new_cap = mem->cap ? mem->cap * 2 : 8192;
        while (new_cap < mem->len + bytes + 1) new_cap *= 2;
        char *new_data = (char *)realloc(mem->data, new_cap);
        if (!new_data) return 0;
        mem->data = new_data;
        mem->cap = new_cap;
    }
    memcpy(mem->data + mem->len, ptr, bytes);
    mem->len += bytes;
    mem->data[mem->len] = '\0';
    return bytes;
}

static void configure_curl_tls(CURL *curl) {
#ifdef _WIN32
#ifdef CURLSSLOPT_NATIVE_CA
    /* Static MSYS2 libcurl normally uses OpenSSL. On Windows there is no PEM
       CA bundle beside the exe, so ask libcurl to use Windows native roots. */
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NATIVE_CA);
#endif
#endif
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
}

static char *get_url_content(const char *target_url, size_t *out_len) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    MemoryBuffer mem;
    memset(&mem, 0, sizeof(mem));
    mem.max_len = MAX_DOWNLOAD_SIZE;
    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, target_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_to_memory);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &mem);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "better-cloudflare-ip-c/2.1.4");
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    configure_curl_tls(curl);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || http_code >= 400 || mem.too_large) {
        if (res != CURLE_OK) {
            const char *msg = errbuf[0] ? errbuf : curl_easy_strerror(res);
            fprintf(stderr, "下载失败: %s\nURL: %s\n", msg, target_url);
        } else if (http_code >= 400) {
            fprintf(stderr, "下载失败: HTTP %ld\nURL: %s\n", http_code, target_url);
        } else if (mem.too_large) {
            fprintf(stderr, "下载失败: 响应超过 %u 字节上限\nURL: %s\n", (unsigned)MAX_DOWNLOAD_SIZE, target_url);
        }
        free(mem.data);
        return NULL;
    }
    if (!mem.data) {
        mem.data = strdup("");
        mem.len = 0;
    }
    if (out_len) *out_len = mem.len;
    return mem.data;
}

/* ----------------------- IP 列表与随机 IP 生成 ----------------------- */

static StringList parse_ip_list(const char *content) {
    StringList list;
    string_list_init(&list);
    if (!content) return list;

    char *copy = strdup(content);
    if (!copy) return list;

    char *saveptr = NULL;
    for (char *line = strtok_r(copy, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
        trim_in_place(line);
        if (line[0] != '\0') string_list_push_dup(&list, line);
    }
    free(copy);
    return list;
}

static StringList random_sample(const StringList *list, size_t n) {
    StringList sampled;
    string_list_init(&sampled);
    if (!list || list->len == 0) return sampled;

    char **shuffled = (char **)malloc(list->len * sizeof(char *));
    if (!shuffled) return sampled;
    for (size_t i = 0; i < list->len; i++) shuffled[i] = list->items[i];

    pthread_mutex_lock(&random_mu);
    for (size_t i = list->len - 1; i > 0; i--) {
        size_t j = (size_t)(next_random_u64_locked() % (uint64_t)(i + 1));
        char *tmp = shuffled[i];
        shuffled[i] = shuffled[j];
        shuffled[j] = tmp;
    }
    pthread_mutex_unlock(&random_mu);

    if (n > list->len) n = list->len;
    for (size_t i = 0; i < n; i++) string_list_push_dup(&sampled, shuffled[i]);
    free(shuffled);
    return sampled;
}

static StringList get_random_ipv4s(const StringList *ip_list) {
    StringList random_ips;
    string_list_init(&random_ips);
    if (!ip_list) return random_ips;

    for (size_t i = 0; i < ip_list->len; i++) {
        char subnet[MAX_IP_LEN];
        snprintf(subnet, sizeof(subnet), "%s", ip_list->items[i]);
        trim_in_place(subnet);
        if (subnet[0] == '\0') continue;

        char *slash = strchr(subnet, '/');
        if (slash) *slash = '\0';

        char *parts[4] = {0};
        char *saveptr = NULL;
        int count = 0;
        for (char *tok = strtok_r(subnet, ".", &saveptr); tok && count < 4; tok = strtok_r(NULL, ".", &saveptr)) {
            parts[count++] = tok;
        }
        if (count == 4) {
            char ip[MAX_IP_LEN];
            snprintf(ip, sizeof(ip), "%s.%s.%s.%d", parts[0], parts[1], parts[2], next_random_intn(256));
            string_list_push_dup(&random_ips, ip);
        }
    }
    return random_ips;
}

static int split_colon_keep_empty(char *s, char parts[][32], int max_parts) {
    int count = 0;
    char *start = s;
    for (char *p = s; ; p++) {
        if (*p == ':' || *p == '\0') {
            if (count < max_parts) {
                size_t len = (size_t)(p - start);
                if (len >= 31) len = 31;
                memcpy(parts[count], start, len);
                parts[count][len] = '\0';
                count++;
            }
            if (*p == '\0') break;
            start = p + 1;
        }
    }
    return count;
}

static StringList get_random_ipv6s(const StringList *ip_list) {
    StringList random_ips;
    string_list_init(&random_ips);
    if (!ip_list) return random_ips;

    for (size_t i = 0; i < ip_list->len; i++) {
        char subnet[256];
        snprintf(subnet, sizeof(subnet), "%s", ip_list->items[i]);
        trim_in_place(subnet);
        if (subnet[0] == '\0') continue;

        char *slash = strchr(subnet, '/');
        if (slash) *slash = '\0';

        char sections[16][32];
        int section_count = 0;
        memset(sections, 0, sizeof(sections));

        char *dbl = strstr(subnet, "::");
        if (dbl) {
            char left[256], right[256];
            size_t left_len = (size_t)(dbl - subnet);
            if (left_len >= sizeof(left)) left_len = sizeof(left) - 1;
            memcpy(left, subnet, left_len);
            left[left_len] = '\0';
            snprintf(right, sizeof(right), "%s", dbl + 2);

            char left_parts[8][32];
            char right_parts[8][32];
            int left_count = 0, right_count = 0;
            memset(left_parts, 0, sizeof(left_parts));
            memset(right_parts, 0, sizeof(right_parts));

            if (left[0] != '\0') left_count = split_colon_keep_empty(left, left_parts, 8);
            else {
                /* 贴近 Go 版 strings.Split("", ":") 的行为 */
                strcpy(left_parts[0], "");
                left_count = 1;
            }
            if (right[0] != '\0') right_count = split_colon_keep_empty(right, right_parts, 8);

            int missing = 8 - left_count - right_count;
            if (missing < 0) continue;
            for (int j = 0; j < left_count && section_count < 16; j++)
                copy_cstr(sections[section_count++], sizeof(sections[0]), left_parts[j]);
            for (int j = 0; j < missing && section_count < 16; j++)
                copy_cstr(sections[section_count++], sizeof(sections[0]), "0");
            for (int j = 0; j < right_count && section_count < 16; j++)
                copy_cstr(sections[section_count++], sizeof(sections[0]), right_parts[j]);
        } else {
            section_count = split_colon_keep_empty(subnet, sections, 16);
        }

        if (section_count >= 3) {
            char ip[256];
            snprintf(ip, sizeof(ip), "%s:%s:%s:%x:%x:%x:%x:%x",
                     sections[0], sections[1], sections[2],
                     next_random_intn(65536), next_random_intn(65536),
                     next_random_intn(65536), next_random_intn(65536),
                     next_random_intn(65536));
            string_list_push_dup(&random_ips, ip);
        }
    }
    return random_ips;
}

/* ----------------------- 数据中心位置解析 ----------------------- */

static uint32_t hash_iata(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

static void location_map_clear(void) {
    pthread_rwlock_wrlock(&location_lock);
    memset(location_table, 0, sizeof(location_table));
    pthread_rwlock_unlock(&location_lock);
}

static void location_map_insert_locked(const char *iata, const char *city) {
    if (!iata || iata[0] == '\0') return;
    uint32_t h = hash_iata(iata);
    for (size_t i = 0; i < LOCATION_TABLE_SIZE; i++) {
        size_t idx = (h + i) % LOCATION_TABLE_SIZE;
        if (!location_table[idx].used || strcmp(location_table[idx].iata, iata) == 0) {
            location_table[idx].used = 1;
            snprintf(location_table[idx].iata, sizeof(location_table[idx].iata), "%s", iata);
            snprintf(location_table[idx].city, sizeof(location_table[idx].city), "%s", city ? city : "");
            return;
        }
    }
}

static int lookup_data_center(const char *colo, char *out, size_t out_size) {
    if (!colo || colo[0] == '\0') {
        if (out_size) out[0] = '\0';
        return 0;
    }
    pthread_rwlock_rdlock(&location_lock);
    uint32_t h = hash_iata(colo);
    for (size_t i = 0; i < LOCATION_TABLE_SIZE; i++) {
        size_t idx = (h + i) % LOCATION_TABLE_SIZE;
        if (!location_table[idx].used) break;
        if (strcmp(location_table[idx].iata, colo) == 0) {
            if (location_table[idx].city[0] != '\0') {
                snprintf(out, out_size, "%s", location_table[idx].city);
            } else {
                snprintf(out, out_size, "%s", colo);
            }
            pthread_rwlock_unlock(&location_lock);
            return 1;
        }
    }
    pthread_rwlock_unlock(&location_lock);
    snprintf(out, out_size, "%s", colo);
    return 0;
}

static void append_utf8(char *out, size_t out_size, size_t *pos, unsigned codepoint) {
    unsigned char bytes[4];
    int count = 0;
    if (codepoint <= 0x7F) {
        bytes[count++] = (unsigned char)codepoint;
    } else if (codepoint <= 0x7FF) {
        bytes[count++] = (unsigned char)(0xC0 | (codepoint >> 6));
        bytes[count++] = (unsigned char)(0x80 | (codepoint & 0x3F));
    } else if (codepoint <= 0xFFFF) {
        bytes[count++] = (unsigned char)(0xE0 | (codepoint >> 12));
        bytes[count++] = (unsigned char)(0x80 | ((codepoint >> 6) & 0x3F));
        bytes[count++] = (unsigned char)(0x80 | (codepoint & 0x3F));
    } else if (codepoint <= 0x10FFFF) {
        bytes[count++] = (unsigned char)(0xF0 | (codepoint >> 18));
        bytes[count++] = (unsigned char)(0x80 | ((codepoint >> 12) & 0x3F));
        bytes[count++] = (unsigned char)(0x80 | ((codepoint >> 6) & 0x3F));
        bytes[count++] = (unsigned char)(0x80 | (codepoint & 0x3F));
    }
    for (int i = 0; i < count && *pos + 1 < out_size; i++) {
        out[(*pos)++] = (char)bytes[i];
    }
    if (out_size) out[*pos < out_size ? *pos : out_size - 1] = '\0';
}

static int hex4(const char *p, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        unsigned x;
        if (c >= '0' && c <= '9') x = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') x = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') x = (unsigned)(c - 'A' + 10);
        else return 0;
        v = (v << 4) | x;
    }
    *out = v;
    return 1;
}

static const char *json_read_string(const char *p, const char *end, char *out, size_t out_size) {
    if (!p || p >= end || *p != '"') return NULL;
    p++;
    size_t pos = 0;
    if (out_size) out[0] = '\0';
    while (p < end && *p) {
        unsigned char c = (unsigned char)*p++;
        if (c == '"') {
            if (out_size) out[pos < out_size ? pos : out_size - 1] = '\0';
            return p;
        }
        if (c == '\\' && p < end) {
            char esc = *p++;
            switch (esc) {
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case '/': c = '/'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'u': {
                    unsigned cp = 0;
                    if (p + 4 <= end && hex4(p, &cp)) {
                        p += 4;
                        /* 处理 UTF-16 surrogate pair */
                        if (cp >= 0xD800 && cp <= 0xDBFF && p + 6 <= end && p[0] == '\\' && p[1] == 'u') {
                            unsigned low = 0;
                            if (hex4(p + 2, &low) && low >= 0xDC00 && low <= 0xDFFF) {
                                p += 6;
                                cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
                            }
                        }
                        append_utf8(out, out_size, &pos, cp);
                        continue;
                    }
                    c = '?';
                    break;
                }
                default: c = (unsigned char)esc; break;
            }
        }
        if (pos + 1 < out_size) out[pos++] = (char)c;
    }
    if (out_size) out[pos < out_size ? pos : out_size - 1] = '\0';
    return NULL;
}

static int json_extract_string(const char *obj_start, const char *obj_end,
                               const char *key, char *out, size_t out_size) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = obj_start;
    size_t pat_len = strlen(pattern);
    while (p && p < obj_end) {
        const char *found = strstr(p, pattern);
        if (!found || found >= obj_end) break;
        p = found + pat_len;
        while (p < obj_end && isspace((unsigned char)*p)) p++;
        if (p >= obj_end || *p != ':') continue;
        p++;
        while (p < obj_end && isspace((unsigned char)*p)) p++;
        if (p < obj_end && *p == '"') {
            return json_read_string(p, obj_end, out, out_size) != NULL;
        }
    }
    if (out_size) out[0] = '\0';
    return 0;
}

/* ----------------------- 连接、RTT、HTTP 响应头检测 ----------------------- */

static int set_fd_blocking(bcf_socket_t fd, int blocking) {
#ifdef _WIN32
    u_long mode = blocking ? 0UL : 1UL;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (blocking) flags &= ~O_NONBLOCK;
    else flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
#endif
}


static int bcf_setsockopt_int(bcf_socket_t fd, int level, int optname, int value) {
#ifdef _WIN32
    const char *optval = (const char *)&value;
#else
    const void *optval = (const void *)&value;
#endif
    return setsockopt(fd, level, optname, optval, (socklen_t)sizeof(value));
}

static int bcf_getsockopt_int(bcf_socket_t fd, int level, int optname, int *value) {
    if (!value) return -1;
#ifdef _WIN32
    int len = (int)sizeof(*value);
    return getsockopt(fd, level, optname, (char *)value, &len);
#else
    socklen_t len = (socklen_t)sizeof(*value);
    return getsockopt(fd, level, optname, value, &len);
#endif
}

static int set_socket_timeout_ms(bcf_socket_t fd, int timeout_ms) {
    if (timeout_ms < 1) timeout_ms = 1;
#ifdef _WIN32
    DWORD tv = (DWORD)timeout_ms;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) != 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv)) != 0) return -1;
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) return -1;
#endif
    return 0;
}

static bcf_socket_t connect_tcp_timeout(const char *ip, int port, int timeout_ms, int *tcp_ms_out) {
    struct sockaddr_storage ss;
    socklen_t ss_len = 0;
    memset(&ss, 0, sizeof(ss));

    if (strchr(ip, ':')) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&ss;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, ip, &addr6->sin6_addr) != 1) return BCF_INVALID_SOCKET;
        ss_len = sizeof(*addr6);
    } else {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&ss;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip, &addr4->sin_addr) != 1) return BCF_INVALID_SOCKET;
        ss_len = sizeof(*addr4);
    }

    bcf_socket_t fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (fd == BCF_INVALID_SOCKET) return BCF_INVALID_SOCKET;

    int one = 1;
    (void)bcf_setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, one);

    if (set_fd_blocking(fd, 0) != 0) {
        BCF_CLOSE_SOCKET(fd);
        return BCF_INVALID_SOCKET;
    }

    long long start = now_ms();
    int rc = connect(fd, (struct sockaddr *)&ss, ss_len);
    if (rc != 0) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            BCF_CLOSE_SOCKET(fd);
            return BCF_INVALID_SOCKET;
        }
#else
        if (errno != EINPROGRESS) {
            BCF_CLOSE_SOCKET(fd);
            return BCF_INVALID_SOCKET;
        }
#endif
    }

    if (rc != 0) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        rc = select((int)(fd + 1), NULL, &wfds, NULL, &tv);
        if (rc <= 0) {
            BCF_CLOSE_SOCKET(fd);
            return BCF_INVALID_SOCKET;
        }
        int so_error = 0;
        if (bcf_getsockopt_int(fd, SOL_SOCKET, SO_ERROR, &so_error) != 0 || so_error != 0) {
            BCF_CLOSE_SOCKET(fd);
            return BCF_INVALID_SOCKET;
        }
    }

    long long elapsed = now_ms() - start;
    if (tcp_ms_out) *tcp_ms_out = (int)elapsed;
    set_fd_blocking(fd, 1);
    return fd;
}

static int wait_fd(bcf_socket_t fd, int want_write, int timeout_ms) {
    if (timeout_ms < 1) return -1;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = select((int)(fd + 1), want_write ? NULL : &fds, want_write ? &fds : NULL, NULL, &tv);
    return rc > 0 ? 0 : -1;
}

static int send_all_deadline(bcf_socket_t fd, const char *buf, size_t len, long long deadline_ms) {
    size_t sent = 0;
    while (sent < len) {
        int rem = (int)(deadline_ms - now_ms());
        if (wait_fd(fd, 1, rem) != 0) return -1;
        bcf_ssize_t n = send(fd, buf + sent, (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int headers_have_cf_ray(const char *headers, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        size_t line_start = pos;
        while (pos < len && headers[pos] != '\n') pos++;
        size_t line_end = pos;
        if (pos < len && headers[pos] == '\n') pos++;

        while (line_start < line_end && (headers[line_start] == '\r' || headers[line_start] == ' ' || headers[line_start] == '\t')) line_start++;
        if (line_end > line_start && headers[line_end - 1] == '\r') line_end--;
        if (line_end - line_start >= 7 && strncasecmp(headers + line_start, "CF-RAY:", 7) == 0) {
            return 1;
        }
    }
    return 0;
}

static int buffer_contains(const char *haystack, size_t haystack_len, const char *needle, size_t needle_len) {
    if (!haystack || !needle || needle_len == 0) return 1;
    if (haystack_len < needle_len) return 0;

    size_t last = haystack_len - needle_len;
    for (size_t i = 0; i <= last; i++) {
        if (haystack[i] == needle[0] && memcmp(haystack + i, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static int buffer_has_header_end(const char *buf, size_t len) {
    if (buffer_contains(buf, len, "\r\n\r\n", 4)) return 1;
    if (buffer_contains(buf, len, "\n\n", 2)) return 1;
    return 0;
}

static int read_headers_raw(bcf_socket_t fd, long long deadline_ms) {
    char headers[MAX_HEADER_SIZE + 1];
    size_t len = 0;
    while (len < MAX_HEADER_SIZE) {
        int rem = (int)(deadline_ms - now_ms());
        if (wait_fd(fd, 0, rem) != 0) return -1;
        bcf_ssize_t n = recv(fd, headers + len, (int)(MAX_HEADER_SIZE - len), 0);
        if (n <= 0) return -1;
        len += (size_t)n;
        headers[len] = '\0';
        if (buffer_has_header_end(headers, len)) {
            return headers_have_cf_ray(headers, len) ? 0 : -1;
        }
    }
    return -1;
}

static void rtt_ssl_init_once(void) {
    rtt_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (rtt_ssl_ctx) {
        SSL_CTX_set_verify(rtt_ssl_ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_options(rtt_ssl_ctx, SSL_OP_NO_COMPRESSION);
    }
}

static int ssl_write_all(SSL *ssl, bcf_socket_t fd, const char *buf, size_t len, long long deadline_ms) {
    size_t sent = 0;
    while (sent < len) {
        int rem = (int)(deadline_ms - now_ms());
        if (rem <= 0) return -1;
        set_socket_timeout_ms(fd, rem);
        int n = SSL_write(ssl, buf + sent, (int)(len - sent));
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int read_headers_ssl(SSL *ssl, bcf_socket_t fd, long long deadline_ms) {
    char headers[MAX_HEADER_SIZE + 1];
    size_t len = 0;
    while (len < MAX_HEADER_SIZE) {
        int rem = (int)(deadline_ms - now_ms());
        if (rem <= 0) return -1;
        set_socket_timeout_ms(fd, rem);
        int n = SSL_read(ssl, headers + len, (int)(MAX_HEADER_SIZE - len));
        if (n <= 0) return -1;
        len += (size_t)n;
        headers[len] = '\0';
        if (buffer_has_header_end(headers, len)) {
            return headers_have_cf_ray(headers, len) ? 0 : -1;
        }
    }
    return -1;
}

static int test_rtt(const char *ip, int use_tls) {
    int port = use_tls ? 443 : 80;
    int total_ms = 0;

    for (int i = 0; i < 3; i++) {
        long long start = now_ms();
        int tcp_ms = 0;
        bcf_socket_t fd = connect_tcp_timeout(ip, port, 1000, &tcp_ms);
        if (fd == BCF_INVALID_SOCKET) return 0;
        total_ms += tcp_ms;

        long long deadline = start + 1000LL;
        int rem = (int)(deadline - now_ms());
        if (rem <= 0) {
            BCF_CLOSE_SOCKET(fd);
            return 0;
        }
        set_socket_timeout_ms(fd, rem);

        const char *req = "GET / HTTP/1.1\r\n"
                          "Host: cloudflare.com\r\n"
                          "User-Agent: Mozilla/5.0\r\n"
                          "Connection: close\r\n\r\n";

        int ok = 0;
        if (use_tls) {
            pthread_once(&rtt_ssl_once, rtt_ssl_init_once);
            if (!rtt_ssl_ctx) {
                BCF_CLOSE_SOCKET(fd);
                return 0;
            }
            SSL *ssl = SSL_new(rtt_ssl_ctx);
            if (!ssl) {
                BCF_CLOSE_SOCKET(fd);
                return 0;
            }
            SSL_set_fd(ssl, fd);
            SSL_set_tlsext_host_name(ssl, "cloudflare.com");
            rem = (int)(deadline - now_ms());
            if (rem > 0) set_socket_timeout_ms(fd, rem);
            if (rem > 0 && SSL_connect(ssl) == 1 &&
                ssl_write_all(ssl, fd, req, strlen(req), deadline) == 0 &&
                read_headers_ssl(ssl, fd, deadline) == 0) {
                ok = 1;
            }
            SSL_free(ssl);
        } else {
            if (send_all_deadline(fd, req, strlen(req), deadline) == 0 &&
                read_headers_raw(fd, deadline) == 0) {
                ok = 1;
            }
        }
        BCF_CLOSE_SOCKET(fd);
        if (!ok) return 0;
    }
    return total_ms / 3;
}

/* ----------------------- 并发 RTT 测试 ----------------------- */

typedef struct {
    const StringList *ip_list;
    size_t next_index;
    size_t completed;
    int use_tls;
    int total;
    pthread_mutex_t index_mu;
    pthread_mutex_t result_mu;
    pthread_mutex_t progress_mu;
    RTTVector results;
} RTTContext;

static void *rtt_worker(void *arg) {
    RTTContext *ctx = (RTTContext *)arg;
    for (;;) {
        pthread_mutex_lock(&ctx->index_mu);
        size_t idx = ctx->next_index++;
        pthread_mutex_unlock(&ctx->index_mu);

        if (idx >= ctx->ip_list->len) break;

        const char *ip = ctx->ip_list->items[idx];
        int avg_ms = test_rtt(ip, ctx->use_tls);
        if (avg_ms > 0) {
            pthread_mutex_lock(&ctx->result_mu);
            rtt_vector_push(&ctx->results, ip, avg_ms);
            pthread_mutex_unlock(&ctx->result_mu);
        }

        pthread_mutex_lock(&ctx->progress_mu);
        ctx->completed++;
        size_t current = ctx->completed;
        pthread_mutex_unlock(&ctx->progress_mu);

        if (current % 10 == 0 || current == (size_t)ctx->total) {
            printf("RTT 测试进度: %zu/%d\n", current, ctx->total);
            fflush(stdout);
        }
    }
    return NULL;
}

static int compare_rtt_result(const void *a, const void *b) {
    const RTTResult *ra = (const RTTResult *)a;
    const RTTResult *rb = (const RTTResult *)b;
    return (ra->latency_ms > rb->latency_ms) - (ra->latency_ms < rb->latency_ms);
}

static RTTVector run_rtt_test(const StringList *ip_list, int task_num, int use_tls) {
    RTTVector empty;
    rtt_vector_init(&empty);
    if (!ip_list || ip_list->len == 0) return empty;

    if ((size_t)task_num > ip_list->len) task_num = (int)ip_list->len;
    if (task_num <= 0) return empty;

    RTTContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ip_list = ip_list;
    ctx.use_tls = use_tls;
    ctx.total = (int)ip_list->len;
    pthread_mutex_init(&ctx.index_mu, NULL);
    pthread_mutex_init(&ctx.result_mu, NULL);
    pthread_mutex_init(&ctx.progress_mu, NULL);
    rtt_vector_init(&ctx.results);

    pthread_t *threads = (pthread_t *)calloc((size_t)task_num, sizeof(pthread_t));
    if (!threads) return empty;

    for (int i = 0; i < task_num; i++) pthread_create(&threads[i], NULL, rtt_worker, &ctx);
    for (int i = 0; i < task_num; i++) pthread_join(threads[i], NULL);
    free(threads);

    pthread_mutex_destroy(&ctx.index_mu);
    pthread_mutex_destroy(&ctx.result_mu);
    pthread_mutex_destroy(&ctx.progress_mu);

    qsort(ctx.results.items, ctx.results.len, sizeof(RTTResult), compare_rtt_result);

    if (ctx.results.len > 10) {
        printf("RTT 测试完成，%zu/%d 个 IP 有效，保留延迟最低的 10 个\n", ctx.results.len, ctx.total);
        ctx.results.len = 10;
    } else {
        printf("RTT 测试完成，%zu/%d 个 IP 有效\n", ctx.results.len, ctx.total);
    }
    return ctx.results;
}

/* ----------------------- 速度测试：使用 libcurl 复刻 Go 的自定义 Dial ----------------------- */

typedef struct {
    long long window_bytes;
    long long window_start_ms;
    int started;
    int max_speed_kbps;
    char cf_ray[256];
    char data_center[32];
} SpeedCtx;

static void extract_data_center(const char *cf_ray, char *out, size_t out_size) {
    if (!cf_ray || cf_ray[0] == '\0') {
        if (out_size) out[0] = '\0';
        return;
    }
    const char *dash = strrchr(cf_ray, '-');
    if (!dash || dash[1] == '\0') {
        if (out_size) out[0] = '\0';
        return;
    }
    snprintf(out, out_size, "%s", dash + 1);
    trim_in_place(out);
}

static size_t speed_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    (void)ptr;
    size_t bytes = size * nmemb;
    SpeedCtx *ctx = (SpeedCtx *)userdata;
    long long now = now_ms();

    if (!ctx->started) {
        ctx->window_start_ms = now;
        ctx->started = 1;
    }

    ctx->window_bytes += (long long)bytes;
    double elapsed = (double)(now - ctx->window_start_ms) / 1000.0;
    if (elapsed >= 1.0) {
        int speed_kb = (int)((double)ctx->window_bytes / 1024.0 / elapsed);
        if (speed_kb > ctx->max_speed_kbps) ctx->max_speed_kbps = speed_kb;
        ctx->window_bytes = 0;
        ctx->window_start_ms = now;
    }
    return bytes;
}

static void speed_finalize(SpeedCtx *ctx) {
    if (!ctx || !ctx->started || ctx->window_bytes <= 0) return;

    long long now = now_ms();
    double elapsed = (double)(now - ctx->window_start_ms) / 1000.0;
    if (elapsed <= 0.0) return;

    int speed_kb = (int)((double)ctx->window_bytes / 1024.0 / elapsed);
    if (speed_kb > ctx->max_speed_kbps) ctx->max_speed_kbps = speed_kb;
}

static size_t speed_header_cb(char *buffer, size_t size, size_t nitems, void *userdata) {
    size_t bytes = size * nitems;
    SpeedCtx *ctx = (SpeedCtx *)userdata;

    const char *colon = memchr(buffer, ':', bytes);
    if (colon) {
        size_t key_len = (size_t)(colon - buffer);
        while (key_len > 0 && isspace((unsigned char)buffer[key_len - 1])) key_len--;
        if (key_len == 6 && strncasecmp(buffer, "CF-RAY", 6) == 0) {
            size_t value_len = bytes - (size_t)(colon - buffer) - 1;
            if (value_len >= sizeof(ctx->cf_ray)) value_len = sizeof(ctx->cf_ray) - 1;
            memcpy(ctx->cf_ray, colon + 1, value_len);
            ctx->cf_ray[value_len] = '\0';
            trim_in_place(ctx->cf_ray);
            extract_data_center(ctx->cf_ray, ctx->data_center, sizeof(ctx->data_center));
        }
    }
    return bytes;
}

static void bracket_ipv6_if_needed(const char *ip, char *out, size_t out_size) {
    if (strchr(ip, ':') && ip[0] != '[') snprintf(out, out_size, "[%s]", ip);
    else snprintf(out, out_size, "%s", ip);
}

static SpeedResult run_speed_test_simple(const char *ip, int port, int use_tls) {
    SpeedResult result;
    memset(&result, 0, sizeof(result));

    if (speed_test_domain[0] == '\0' || speed_test_file[0] == '\0') {
        return result;
    }

    CURL *curl = curl_easy_init();
    if (!curl) return result;

    const char *scheme = use_tls ? "https" : "http";
    int default_url_port = use_tls ? 443 : 80;
    char url[2048];
    snprintf(url, sizeof(url), "%s://%s/%s", scheme, speed_test_domain, speed_test_file);

    char connect_ip[256];
    bracket_ipv6_if_needed(ip, connect_ip, sizeof(connect_ip));

    char connect_to_entry[2048];
    snprintf(connect_to_entry, sizeof(connect_to_entry), "%s:%d:%s:%d",
             speed_test_domain, default_url_port, connect_ip, port);
    struct curl_slist *connect_to = NULL;
    connect_to = curl_slist_append(connect_to, connect_to_entry);

    SpeedCtx ctx;
    memset(&ctx, 0, sizeof(ctx));

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CONNECT_TO, connect_to);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, speed_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, speed_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 32L * 1024L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    if (use_tls) {
        configure_curl_tls(curl);
    }

    CURLcode res = curl_easy_perform(curl);
    speed_finalize(&ctx);

    long response_code = 0;
    curl_off_t downloaded = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &downloaded);

    if ((res == CURLE_OK || res == CURLE_OPERATION_TIMEDOUT) &&
        response_code >= 200 && response_code < 300 &&
        downloaded > 0) {
        curl_off_t connect_us = 0;
        if (curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME_T, &connect_us) == CURLE_OK) {
            result.tcp_ms = (int)(connect_us / 1000);
        }
        result.max_speed_kbps = ctx.max_speed_kbps;
        snprintf(result.data_center, sizeof(result.data_center), "%s", ctx.data_center);
    }

    curl_slist_free_all(connect_to);
    curl_easy_cleanup(curl);
    return result;
}

/* ----------------------- 数据文件下载与初始化 ----------------------- */

#define DATA_CDN_BASE "https://cdn.jsdelivr.net/gh/fscarmen/better-cloudflare-ip@main"
#define REMOTE_URL_TXT DATA_CDN_BASE "/url.txt"
#define REMOTE_IPS_V4_TXT DATA_CDN_BASE "/ips-v4.txt"
#define REMOTE_IPS_V6_TXT DATA_CDN_BASE "/ips-v6.txt"
#define REMOTE_LOCATIONS_JSON DATA_CDN_BASE "/locations.json"

static void download_all_data(void) {
    char path[PATH_MAX];
    data_path("url.txt", path, sizeof(path));
    if (!file_exists(path)) {
        printf("本地 %s 不存在，正在下载...\n", path);
        size_t len = 0;
        char *content = get_url_content(REMOTE_URL_TXT, &len);
        if (!content) {
            printf("下载测速 URL 失败，使用内置备用 URL\n");
            if (save_text_to_file(path, FALLBACK_URL_TXT) != 0) {
                printf("保存内置测速 URL 失败\n");
                return;
            }
        } else if (save_to_file(path, content, len) != 0) {
            printf("保存测速 URL 失败\n");
            free(content);
            return;
        }
        free(content);
    }

    size_t url_len = 0;
    char *url_content = get_file_content(path, &url_len);
    if (!url_content) {
        printf("读取测速 URL 失败\n");
        return;
    }
    (void)url_len;
    trim_in_place(url_content);
    char *slash = strchr(url_content, '/');
    if (slash) {
        *slash = '\0';
        snprintf(speed_test_domain, sizeof(speed_test_domain), "%s", url_content);
        snprintf(speed_test_file, sizeof(speed_test_file), "%s", slash + 1);
    } else {
        printf("测速 URL 格式异常\n");
    }
    free(url_content);

    struct {
        const char *file;
        const char *url;
    } downloads[] = {
        {"ips-v4.txt", REMOTE_IPS_V4_TXT},
        {"ips-v6.txt", REMOTE_IPS_V6_TXT},
    };

    for (size_t i = 0; i < sizeof(downloads) / sizeof(downloads[0]); i++) {
        data_path(downloads[i].file, path, sizeof(path));
        if (!file_exists(path)) {
            printf("本地 %s 不存在，正在下载...\n", path);
            size_t len = 0;
            char *content = get_url_content(downloads[i].url, &len);
            if (!content) {
                const char *fallback = strcmp(downloads[i].file, "ips-v6.txt") == 0 ? FALLBACK_IPS_V6_TXT : FALLBACK_IPS_V4_TXT;
                printf("下载 IP 列表失败，使用内置备用 %s\n", downloads[i].file);
                if (save_text_to_file(path, fallback) != 0) {
                    printf("保存内置 IP 列表失败\n");
                    return;
                }
            } else if (save_to_file(path, content, len) != 0) {
                printf("保存 IP 列表失败\n");
                free(content);
                return;
            }
            free(content);
        }
    }

    data_path("locations.json", path, sizeof(path));
    if (!file_exists(path)) {
        printf("本地 %s 不存在，正在下载...\n", path);
        size_t len = 0;
        char *content = get_url_content(REMOTE_LOCATIONS_JSON, &len);
        if (!content) {
            printf("获取位置信息失败，使用内置备用 locations.json\n");
            if (save_text_to_file(path, FALLBACK_LOCATIONS_JSON) != 0) {
                printf("保存内置位置信息失败\n");
                return;
            }
        } else if (save_to_file(path, content, len) != 0) {
            printf("保存位置信息失败\n");
            free(content);
            return;
        }
        free(content);
    }
}

static void init_locations(void) {
    download_all_data();

    char path[PATH_MAX];
    data_path("locations.json", path, sizeof(path));
    size_t len = 0;
    char *body = get_file_content(path, &len);
    if (!body) {
        printf("读取位置文件失败，使用内置备用 locations.json\n");
        body = strdup(FALLBACK_LOCATIONS_JSON);
        if (!body) return;
        len = strlen(body);
    }

    location_map_clear();
    size_t loaded = 0;

    pthread_rwlock_wrlock(&location_lock);
    const char *p = body;
    const char *end = body + len;
    while (p < end) {
        const char *obj_start = strchr(p, '{');
        if (!obj_start || obj_start >= end) break;
        const char *obj_end = strchr(obj_start, '}');
        if (!obj_end || obj_end > end) break;

        char iata[32] = "";
        char city[256] = "";
        if (json_extract_string(obj_start, obj_end, "iata", iata, sizeof(iata))) {
            json_extract_string(obj_start, obj_end, "city", city, sizeof(city));
            location_map_insert_locked(iata, city);
            loaded++;
        }
        p = obj_end + 1;
    }
    pthread_rwlock_unlock(&location_lock);

    free(body);
    printf("已加载 %zu 个数据中心位置信息\n", loaded);
}

/* ----------------------- 主流程 ----------------------- */

static CloudflareResult cloudflare_test(int ip_type, int use_tls, int task_num, int speed_threshold_kbps) {
    CloudflareResult final_result;
    memset(&final_result, 0, sizeof(final_result));

    download_all_data();

    char filename[PATH_MAX];
    data_path(ip_type == 6 ? "ips-v6.txt" : "ips-v4.txt", filename, sizeof(filename));
    size_t content_len = 0;
    char *content = get_file_content(filename, &content_len);
    if (!content) {
        printf("读取 IP 列表失败，使用内置备用列表\n");
        content = strdup(ip_type == 6 ? FALLBACK_IPS_V6_TXT : FALLBACK_IPS_V4_TXT);
        if (!content) return final_result;
        content_len = strlen(content);
    }
    (void)content_len;

    StringList ip_list = parse_ip_list(content);
    free(content);

    printf("正在从 %zu 个子网中随机生成 IP...\n", ip_list.len);

    size_t sample_size = 100;
    if (ip_list.len < sample_size) sample_size = ip_list.len;

    for (;;) {
        RTTVector rtt_results;
        rtt_vector_init(&rtt_results);

        while (rtt_results.len == 0) {
            StringList sampled = random_sample(&ip_list, sample_size);
            StringList test_ips = ip_type == 6 ? get_random_ipv6s(&sampled) : get_random_ipv4s(&sampled);

            printf("已生成 %zu 个测试 IP，开始 RTT 测试...\n", test_ips.len);
            rtt_results = run_rtt_test(&test_ips, task_num, use_tls);

            string_list_free(&sampled);
            string_list_free(&test_ips);

            if (rtt_results.len > 0) break;
            rtt_vector_free(&rtt_results);
            printf("当前所有 IP 都存在 RTT 丢包，继续新的 RTT 测试...\n");
        }

        printf("待测速的 IP 地址\n");
        for (size_t i = 0; i < rtt_results.len; i++) {
            printf("%s 往返延迟 %d 毫秒\n", rtt_results.items[i].ip, rtt_results.items[i].latency_ms);
        }

        for (size_t i = 0; i < rtt_results.len; i++) {
            const char *ip = rtt_results.items[i].ip;
            printf("正在测试 %s\n", ip);
            int speed_port = use_tls ? 443 : 80;
            SpeedResult sr = run_speed_test_simple(ip, speed_port, use_tls);

            printf("%s 峰值速度 %d kB/s", ip, sr.max_speed_kbps);
            if (sr.data_center[0] != '\0') {
                char city[256];
                lookup_data_center(sr.data_center, city, sizeof(city));
                printf(", 数据中心 %s", city);
            }
            printf("\n");

            if (sr.max_speed_kbps >= speed_threshold_kbps) {
                snprintf(final_result.ip, sizeof(final_result.ip), "%s", ip);
                final_result.max_speed_kbps = sr.max_speed_kbps;
                final_result.tcp_ms = sr.tcp_ms;
                if (sr.data_center[0] != '\0') {
                    lookup_data_center(sr.data_center, final_result.data_center, sizeof(final_result.data_center));
                } else {
                    final_result.data_center[0] = '\0';
                }
                rtt_vector_free(&rtt_results);
                string_list_free(&ip_list);
                return final_result;
            }
        }

        rtt_vector_free(&rtt_results);
        printf("当前所有 IP 都未达到期望带宽，重新开始新一轮测试...\n");
    }
}

static void run_ip_selector(int ip_type, int use_tls) {
    int bandwidth = 1;
    int task_num = 50;
    char input[MAX_LINE_LEN];

    printf("请设置期望的带宽大小 (默认最小 1，单位 Mbps): ");
    if (read_line_trim(input, sizeof(input))) {
        if (input[0] == '\0') {
            bandwidth = 1;
        } else {
            char *endptr = NULL;
            long val = strtol(input, &endptr, 10);
            if (endptr == input || *endptr != '\0' || val <= 0) {
                printf("输入无效，已使用默认值 1 Mbps\n");
                bandwidth = 1;
            } else {
                bandwidth = (int)val;
            }
        }
    }

    printf("请设置 RTT 测试进程数 (默认 50，最大 100): ");
    if (read_line_trim(input, sizeof(input))) {
        if (input[0] == '\0') {
            task_num = 50;
        } else {
            char *endptr = NULL;
            long val = strtol(input, &endptr, 10);
            if (endptr == input || *endptr != '\0') {
                printf("输入无效，已使用默认值 50\n");
                task_num = 50;
            } else if (val <= 0) {
                printf("进程数不能为 0，自动设置为默认值\n");
                task_num = 50;
            } else {
                task_num = (int)val;
            }
            if (task_num > 100) {
                printf("超过最大进程限制，自动设置为最大值\n");
                task_num = 100;
            }
        }
    }

    int speed = bandwidth * 128;
    long long start = now_ms();
    CloudflareResult res = cloudflare_test(ip_type, use_tls, task_num, speed);
    long long end = now_ms();

    int real_bandwidth = res.max_speed_kbps / 128;
    printf("\n");
    printf("优选 IP: %s\n", res.ip);
    printf("设置带宽: %d Mbps\n", bandwidth);
    printf("实测带宽: %d Mbps\n", real_bandwidth);
    printf("峰值速度: %d kB/s\n", res.max_speed_kbps);
    printf("往返延迟: %d 毫秒\n", res.tcp_ms);
    printf("数据中心: %s\n", res.data_center);
    printf("总计用时: %lld 秒\n", (end - start) / 1000LL);
}

static void run_single_speed_test(int use_tls) {
    char input[MAX_LINE_LEN];
    char ip[MAX_IP_LEN];

    printf("请输入需要测速的 IP: ");
    if (!read_line_trim(ip, sizeof(ip))) return;

    int default_port = use_tls ? 443 : 80;
    int port = default_port;
    printf("请输入需要测速的端口 (默认%d): ", default_port);
    if (read_line_trim(input, sizeof(input))) {
        if (input[0] == '\0') {
            port = default_port;
        } else {
            char *endptr = NULL;
            long val = strtol(input, &endptr, 10);
            if (endptr == input || *endptr != '\0' || val <= 0 || val > 65535) {
                printf("输入无效，已使用默认端口 %d\n", default_port);
                port = default_port;
            } else {
                port = (int)val;
            }
        }
    }

    printf("正在测速 %s 端口 %d\n", ip, port);
    SpeedResult sr = run_speed_test_simple(ip, port, use_tls);
    if (sr.data_center[0] != '\0') {
        char city[256];
        lookup_data_center(sr.data_center, city, sizeof(city));
        printf("%s 平均速度 %d kB/s, TCP延迟 %dms, 数据中心=%s\n",
               ip, sr.max_speed_kbps, sr.tcp_ms, city);
    } else {
        printf("%s 平均速度 %d kB/s, TCP延迟 %dms\n", ip, sr.max_speed_kbps, sr.tcp_ms);
    }
}

static void clear_cache(void) {
    const char *files[] = {"locations.json", "ips-v4.txt", "ips-v6.txt", "url.txt"};
    char path[PATH_MAX];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        data_path(files[i], path, sizeof(path));
        remove(path);
    }
    printf("缓存已清空，下次操作会自动重新下载数据\n");
}

static void update_data(void) {
    printf("正在重新下载数据...\n");
    const char *files[] = {"locations.json", "ips-v4.txt", "ips-v6.txt", "url.txt"};
    char path[PATH_MAX];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        data_path(files[i], path, sizeof(path));
        remove(path);
    }
    init_locations();
}

static void show_menu(void) {
    char input[MAX_LINE_LEN];
    for (;;) {
        printf("----------------------------------------\n");
        printf("1. IPV4 优选 (TLS)\n");
        printf("2. IPV4 优选 (非 TLS)\n");
        printf("3. IPV6 优选 (TLS)\n");
        printf("4. IPV6 优选 (非 TLS)\n");
        printf("5. 单 IP 测速 (TLS)\n");
        printf("6. 单 IP 测速 (非 TLS)\n");
        printf("7. 清空缓存\n");
        printf("8. 更新数据\n");
        printf("0. 退出\n");
        printf("请选择菜单 (默认 0): ");

        if (!read_line_trim(input, sizeof(input))) break;
        if (input[0] == '\0') snprintf(input, sizeof(input), "0");

        if (strcmp(input, "0") == 0) {
            printf("退出成功\n");
            return;
        } else if (strcmp(input, "1") == 0) {
            run_ip_selector(4, 1);
        } else if (strcmp(input, "2") == 0) {
            run_ip_selector(4, 0);
        } else if (strcmp(input, "3") == 0) {
            run_ip_selector(6, 1);
        } else if (strcmp(input, "4") == 0) {
            run_ip_selector(6, 0);
        } else if (strcmp(input, "5") == 0) {
            run_single_speed_test(1);
        } else if (strcmp(input, "6") == 0) {
            run_single_speed_test(0);
        } else if (strcmp(input, "7") == 0) {
            clear_cache();
        } else if (strcmp(input, "8") == 0) {
            update_data();
        } else {
            printf("无效输入，请重新选择\n");
        }
    }
}

int main(int argc, char **argv) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    platform_init();

    const char *env_dir = getenv("BETTER_CF_IP_DATA_DIR");
    if (env_dir && env_dir[0] != '\0') {
        snprintf(data_dir, sizeof(data_dir), "%s", env_dir);
    }
    if (argc == 3 && strcmp(argv[1], "--data-dir") == 0) {
        snprintf(data_dir, sizeof(data_dir), "%s", argv[2]);
    }

    init_random();
    curl_global_init(CURL_GLOBAL_DEFAULT);
    OPENSSL_init_ssl(0, NULL);

    init_locations();
    show_menu();

    if (rtt_ssl_ctx) SSL_CTX_free(rtt_ssl_ctx);
    curl_global_cleanup();
    platform_cleanup();
    return 0;
}
