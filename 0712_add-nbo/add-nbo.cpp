#include "add-nbo.h"

void add_nbo(char *fname1, char *fname2){
    uint32_t a, b, sum;
    uint8_t File_read_buffer[4];
    uint32_t* p;


    FILE *fa = fopen(fname1, "r");
    FILE *fb = fopen(fname2, "r");


    fread(File_read_buffer, sizeof(uint8_t), 4, fa);
    p = reinterpret_cast<uint32_t*>(File_read_buffer);
    a = ntohl(*p);

    fread(File_read_buffer, sizeof(uint8_t), 4, fb);
    p = reinterpret_cast<uint32_t*>(File_read_buffer);
    b = ntohl(*p);

    sum = a + b;
    printf("%d(0x%x) + %d(0x%x)", a, a, b, b);
    printf(" = %d(0x%x)\n", sum, sum);
    
    fclose(fb);
    fclose(fa);
}
