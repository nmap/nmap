#ifndef NSE_STRING
#define NSE_STRING

int nse_isprint(int c);
char* nse_hexify(const void *data, unsigned int data_len);
char* nse_printable(const void *data, unsigned int data_len);

#endif
