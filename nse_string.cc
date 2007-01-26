#ifndef NOLUA

#include "nse_string.h"

#include "nbase.h"
#include "nse_macros.h"

#include <sstream>
#include <iomanip>

int nse_isprint(int c) {
	return ISPRINT(c);
}

char* nse_printable(const void *data, unsigned int data_len) {
	const unsigned char* c_data = (const unsigned char*) data;
	char* result = (char*) safe_malloc((data_len+1)*sizeof(char));
	unsigned int i;

	for(i = 0; i < data_len; i++) {
		if(nse_isprint(c_data[i]))
			result[i] = c_data[i];
		else
			result[i] = NOT_PRINTABLE;
	}

	result[i] = '\0';

	return result;
}

char* nse_hexify(const void *data, unsigned int data_len) { 
	std::ostringstream osDump; 
	std::ostringstream osNums; 
	std::ostringstream osChars; 

	const unsigned char* c_data = (const unsigned char*) data;

	unsigned long i; 
	unsigned int width = 16;
	unsigned long printable_chars = 0;

	// if more than 95% of all characters are printable, we don't hexify
	for(i = 0; i < data_len; i++) {
		if(nse_isprint(c_data[i]))
			printable_chars++;
	}

	if((double)printable_chars > (double)data_len * 95.0 / 100.0) {
		return nse_printable(data, data_len);
	}
		
	osDump << std::endl;
	for(i = 0; i < data_len; i++) 
	{ 
		if(i < data_len) 
		{ 
			char c = c_data[i]; 
			unsigned short n = (unsigned short)c_data[i]; 
			osNums << std::setbase(16) << std::setw(2) << std::setfill('0') << n << " "; 
			osChars << ((n < 32) || (n > 126) ? NOT_PRINTABLE : c); 
		} 
		if(((i % width) == width - 1) || ((i == data_len) && (osNums.str().size() > 0))) 
		{ 
			osDump 	<< std::setbase(16) 
				<< std::setw(8) 
				<< std::setfill('0') 
				<< (i - (i % width)) << ": " 
				<< std::setfill(' ') 
				<< std::setiosflags(std::ios_base::left) 
				<< std::setw(3 * width) 
				<< osNums.str() 
				<< osChars.str() 
				<< std::resetiosflags(std::ios_base::left) 
				<< std::endl; 
			osNums.str(""); 
			osChars.str(""); 
		} 
	} 

	return strdup(osDump.str().c_str());
}

#endif
