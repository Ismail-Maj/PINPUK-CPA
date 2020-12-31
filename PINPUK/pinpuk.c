#include <io.h>
#include <inttypes.h>
#include <avr/eeprom.h>

typedef enum {
  VIERGE,
  VEROUILLE,
  BLOQUE,
  DEVEROUILLE
} etats;

uint8_t ee_puk[8] EEMEM = {0,0,0,0,0,0,0,0};

uint8_t ee_pin[8] EEMEM = {0,0,0,0,0,0,0,0};

uint8_t ee_nbEssaisRestant EEMEM = {0};

etats state = VIERGE;

void sendbytet0(uint8_t b);
uint8_t recbytet0(void);

uint8_t cla, ins, p1, p2, p3;
uint8_t sw1, sw2;

void perso(){
  if(p3!=8){
    sw1=0x6c;	// P3 incorrect
    sw2=8;
    return;
  }
  if(state!=VIERGE){
    sw1=0x66;
    return;
  }
  sendbytet0(ins);
  uint8_t data[8];
  for(int i = 0 ; i < 8; i++){
    data[i] = recbytet0();
  }
  for(int i = 0 ; i < 8; i++){
    eeprom_write_byte(&(ee_puk[i]),data[i]);
  }

    eeprom_write_byte(&(ee_nbEssaisRestant),3);
  state = VEROUILLE;
  sw1=0x90;
}

void intro_pin(){
  if(p3!=8){
    sw1=0x6c;	// P3 incorrect
    sw2=8;
    return;
  }
  if(state!=VEROUILLE){
    sw1=0x66;
    return;
  }

  sendbytet0(ins);
  uint8_t data[8];
  for(int i = 0 ; i < 8; i++){
    data[i] = recbytet0();
  }
  int c = 0;
  for(int i = 0 ; i < 8; i++){
    c+=data[i]^eeprom_read_byte(&(ee_pin[i]));
    if(c != 0){break;}
  }
  if(c == 0){
    state = DEVEROUILLE;
    eeprom_write_byte(&(ee_nbEssaisRestant),3);
  }else{
    uint8_t nb = eeprom_read_byte(&(ee_nbEssaisRestant));
    if(nb == 1){
      state = BLOQUE;
      eeprom_write_byte(&(ee_nbEssaisRestant),255);
      sw2=255;
    }else{
      eeprom_write_byte(&(ee_nbEssaisRestant),nb-1);
      sw2=nb-1;
    }
  }
  sw1=0x90;
}

void change_pin(){
  if(p3!=16){
    sw1=0x6c;	// P3 incorrect
    sw2=8;
    return;
  }
  if(state!=DEVEROUILLE){
    sw1=0x66;	//carte deja perso
    return;
  }
  sendbytet0(ins);
  uint8_t pin[8];
  for(int i = 0 ; i < 8; i++){
    pin[i] = recbytet0();
  }
  uint8_t new_pin[8];
  for(int i = 0 ; i < 8; i++){
    new_pin[i] = recbytet0();
  }

  int c = 0;
  for(int i = 0 ; i < 8; i++){
    c+=pin[i]^eeprom_read_byte(&(ee_pin[i]));
    if(c != 0){break;}
  }
  if(c == 0){
    for(int i = 0 ; i < 8; i++){
      eeprom_write_byte(&(ee_pin[i]),new_pin[i]);
    }
  }else{
    sw2=255;
  }
  sw1=0x90;
}

void intro_puk(){
  if(p3!=16){
    sw1=0x6c;	// P3 incorrect
    sw2=8;
    return;
  }
  if(state!=BLOQUE){
    sw1=0x66;
    return;
  }
  sendbytet0(ins);
  uint8_t puk[8];
  for(int i = 0 ; i < 8; i++){
    puk[i] = recbytet0();
  }
  uint8_t new_pin[8];
  for(int i = 0 ; i < 8; i++){
    new_pin[i] = recbytet0();
  }
  int c = 0;
  for(int i = 0 ; i < 8; i++){
    c+=puk[i]^eeprom_read_byte(&(ee_puk[i]));
    if(c != 0){break;}
  }
  if(c == 0){
    state = VEROUILLE;
    for(int i = 0 ; i < 8; i++){
      eeprom_write_byte(&(ee_pin[i]),new_pin[i]);
    }
    eeprom_write_byte(&(ee_nbEssaisRestant),3);
  }else{
    sw2=1;
  }
  sw1=0x90;
}


void atr(uint8_t n, char* hist)
{
    	sendbytet0(0x3b);	// d�finition du protocole
    	sendbytet0(n);		// nombre d'octets d'historique
    	while(n--)		// Boucle d'envoi des octets d'historique
    	{
        	sendbytet0(*hist++);
    	}
}

int main(){
  ACSR=0x80;
  DDRB=0xff;
  DDRC=0xff;
  DDRD=0;
  PORTB=0xff;
  PORTC=0xff;
  PORTD=0xff;
  ASSR=1<<EXCLK;
  TCCR2A=0;
  ASSR|=1<<AS2;

  atr(7,"pin_puk");

  uint8_t c = eeprom_read_byte(&ee_nbEssaisRestant);
  if(c==0){
    state = VIERGE;
  }else if(c<4){
    state = VEROUILLE;
  }else{
    state = BLOQUE;
  }


  while(1){
    cla=recbytet0();
    ins=recbytet0();
    p1=recbytet0();
    p2=recbytet0();
    p3=recbytet0();
    sw2=0;
    switch (cla){
      case 0xA0:
      switch(ins){
        case 0x20:
        intro_pin();
        break;
        case 0x24:
        change_pin();
        break;
        case 0x2C:
        intro_puk();
        break;
        case 0x40:
        perso();
        break;
        default:
        sw1=0x6d; // code erreur ins inconnu
      }
      break;
      default:
      sw1=0x6e; // code erreur classe inconnue
    }
    sendbytet0(sw1); // envoi du status word
    sendbytet0(sw2);
  }
  return 0;
}
