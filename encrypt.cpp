//c++ implmentation of DES encyption and decryption as well as the sub key generation

//compilation instructions: 
//compiled like normally on command line once in directory by doing % g++ -o encrypt encrypt.cpp 
//code can also be runned in VS code by pressing the play button in the top right corner 

#include <iostream>
#include <string>
#include <cmath>
#include <ostream>


 std::string sKey_48bits[16];

class des{

 //plaintext permutation, expansion, and subtitution tables                                                                                                                                                 

    // intital permutation table                                                                                                                                                                            
    const int IP[64] = {    58 ,50 ,42 ,34 ,26 ,18 ,10 ,2 ,
                            60 ,52 ,44 ,36 ,28 ,20 ,12 ,4 ,
                            62 ,54 ,46 ,38 ,30 ,22 ,14 ,6 ,
                            64 ,56 ,48 ,40 ,32 ,24 ,16 ,8 ,
                            57 ,49 ,41 ,33 ,25 ,17 ,9  ,1 ,
                            59 ,51 ,43 ,35 ,27 ,19 ,11 ,3 ,
                            61 ,53 ,45 ,37 ,29 ,21 ,13 ,5 ,
                            63 ,55 ,47 ,39 ,31 ,23 ,15 ,7 };

  //inverse IP table                                                                                                                                                                                        
    const int IP_inverse[64] = { 40 ,8  ,48 ,16 ,56 ,24 ,64 ,32 ,
                                 39 ,7  ,47 ,15 ,55 ,23 ,63 ,31 ,
                                 38 ,6  ,46 ,14 ,54 ,22 ,62 ,30 ,
                                 37 ,5  ,45 ,13 ,53 ,21 ,61 ,29 ,
                                 36 ,4  ,44 ,12 ,52 ,20 ,60 ,28 ,
                                 35 ,3  ,43 ,11 ,51 ,19 ,59 ,27 ,
                                 34 ,2  ,42 ,10 ,50 ,18 ,58 ,26 ,
                                 33 ,1  ,41 ,9  ,49 ,17 ,57 ,25 };


     // expantion table                                                                                                                                                                                     
        const int Expansion[48] = {     32 ,1  ,2  ,3  ,4  ,5  ,
                                        4  ,5  ,6  ,7  ,8  ,9  ,
                                        8  ,9  ,10 ,11 ,12 ,13 ,
                                        12 ,13 ,14 ,15 ,16 ,17 ,
                                        16 ,17 ,18 ,19 ,20 ,21 ,
                                        20 ,21 ,22 ,23 ,24 ,25 ,
                                        24 ,25 ,26 ,27 ,28 ,29 ,
                                        28 ,29 ,30 ,31 ,32 ,1 };
  //Permutation function table                                                                                                                                                                              
  const int PermutationF[32] = {    16 ,7  ,20 ,21 ,
                                    29 ,12 ,28 ,17 ,
                                    1  ,15 ,23 ,26 ,
                                    5  ,18 ,31 ,10 ,
                                    2  ,8  ,24 ,14 ,
                                    32 ,27 ,3  ,9  ,
                                    19 ,13 ,30 ,6  ,
                                    22 ,11 ,4  ,25 };


 //sboxes                                                                                                                                                                                                  
  //8 sboxes each with 4 rows and 16 columns                                                                                                                                                                
int sBox[8][4][16] = {
                {
                        { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
                        { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
                        { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
                        { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
                },
                {
                        { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
                        { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
                        { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
                        { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
                },
                {       { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
                        { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
                        { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
                        { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
                },
                {
                        { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
                        { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
                        { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
                        { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
                },
                {
                        { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
                        { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
                        { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
                        { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
                },
                {
                        { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
                        { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
                        { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
                        { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
                },
                {
                        { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
                        { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
                        { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
                        { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
                },
                {
                        { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
                        { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
                        { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
                        { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
                }
        };




    //key permutation tables                                                                                                                                                                                

    const int PC1[56] = {   57 ,49 ,41 ,33 ,25 ,17 ,9  ,
                            1  ,58 ,50 ,42 ,34 ,26 ,18 ,
                            10 ,2  ,59 ,51 ,43 ,35 ,27 ,
                            19 ,11 ,3  ,60 ,52 ,44 ,36 ,
                            63 ,55 ,47 ,39 ,31 ,23 ,15 ,
                            7  ,62 ,54 ,46 ,38 ,30 ,22 ,
                            14 ,6  ,61 ,53 ,45 ,37 ,29 ,
                            21 ,13 ,5  ,28 ,20 ,12 ,4 };


    int leftShift[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

 const int PC2[48] = {   14 ,17 ,11 ,24 ,1  ,5  ,
                            3  ,28 ,15 ,6  ,21 ,10 ,
                            23 ,19 ,12 ,4  ,26 ,8  ,
                            16 ,7  ,27 ,20 ,13 ,2  ,
                            41 ,52 ,31 ,37 ,47 ,55 ,
                            30 ,40 ,51 ,45 ,33 ,48 ,
                            44 ,49 ,39 ,56 ,34 ,53 ,
                            46 ,42 ,50 ,36 ,29 ,32 };



    private:

    public:

  //function to convert hexaadecimal values to binary values 
  //returns the binary representation of number 
      std::string hexaToBin( std::string hexadecimal){

      //binary number stored in binary var
      //loop and swith statement to go though each char in hexadeciaml number and assign proper binary representation depending on case
      //for example if 3 showed up in the hexadecimal nunmber we would replace that with 0011 in binary 
      std::string binary = "";
        for (int i = 0; i < hexadecimal.size(); i++)
        {
                switch (hexadecimal[i])
                {
                case '0': binary = binary + "0000";
             break;
                case '1': binary = binary + "0001";
             break;
                case '2': binary = binary + "0010";
            break;
                case '3': binary = binary + "0011";
            break;
                case '4': binary = binary + "0100";
            break;
                case '5': binary = binary + "0101";
            break;
                case '6': binary = binary + "0110";
            break;
                case '7': binary = binary + "0111";
            break;
                case '8': binary = binary + "1000";
            break;
                case '9': binary = binary + "1001";
            break;
                case 'A':
                case 'a': binary = binary + "1010";
            break;
                case 'B':
                case 'b': binary = binary + "1011";
            break;
                case 'C':
                case 'c': binary = binary + "1100";
            break;
                case 'D':
                case 'd': binary = binary + "1101";
            break;
                case 'E':
                case 'e': binary = binary + "1110";
            break;
                case 'F':
                case 'f': binary = binary + "1111";

            break;

                }

        }
        return binary;
    }

//function to convert binary to hexadeciaml numbers
 std::string BintoHexa(std::string binary){

  //loop and switch statment to check groups of four char in binary number and assign them a signle hexadecimal value 
  std::string hexadecimal = "";
        for (int i = 0; i < binary.size(); i = i+4)
        {
          std::string tempBin = "";

                for (int j = i; j < i + 4; j++)
                        tempBin += binary[j];
                if (tempBin == "0000")
                        hexadecimal = hexadecimal + '0';
                else if (tempBin == "0001")
                        hexadecimal = hexadecimal + '1';
                else if (tempBin == "0010")
                        hexadecimal = hexadecimal + '2';
                else if (tempBin == "0011")
                        hexadecimal = hexadecimal + '3';
                else if (tempBin == "0100")
                        hexadecimal = hexadecimal + '4';
                else if (tempBin == "0101")
                        hexadecimal = hexadecimal + '5';
                else if (tempBin == "0110")
                        hexadecimal = hexadecimal + '6';
                else if (tempBin == "0111")
                        hexadecimal = hexadecimal + '7';
                else if (tempBin == "1000")
                        hexadecimal = hexadecimal + '8';
		else if (tempBin == "1001")
			hexadecimal = hexadecimal + '9';
                else if (tempBin == "1010")
                        hexadecimal = hexadecimal + 'A';
                else if (tempBin == "1011")
                        hexadecimal = hexadecimal + 'B';
                else if (tempBin == "1100")
                        hexadecimal = hexadecimal + 'C';
                else if (tempBin == "1101")
                        hexadecimal = hexadecimal + 'D';
                else if (tempBin == "1110")
                        hexadecimal = hexadecimal + 'E';
                else if (tempBin == "1111")
                        hexadecimal = hexadecimal + 'F';
        }
        return hexadecimal;
}

//function to convery binary to decimal
int BinToDec(std::string binary)
{
    int decimal = 0;
	int j = 0;
	int length = binary.length();
	for(int i = length-1; i >= 0; i--){

    	if(binary[i] == '1'){
        decimal += pow(2, j);
    	}
    j++;
	}
	return decimal;

}

//fucntion to do circular left shifts by 1
std::string shiftOnce(std::string key){ 
    std::string keyShifted="";  

        for(int i = 1; i < 28; i++){ 
            keyShifted = keyShifted + key[i]; 
        } 
        keyShifted = keyShifted + key[0];   
    return keyShifted; 
} 
// Function to do a circular left shift by 2
std::string ShiftTwice(std::string key){ 
    std::string keyShifted=""; 

    for(int i = 0; i < 2; i++){ 
        for(int j = 1; j < 28; j++){ 
            keyShifted = keyShifted +  key[j]; 
        } 
        keyShifted = keyShifted +  key[0]; 
        key= keyShifted; 
        keyShifted =""; 
    } 
    return key; 
}


//fucntion to convery decimal to binary 
std::string DecToBin(int decimal)
{
	std::string binary = "";
	while (decimal > 0)
	{
		binary = (char)(decimal % 2 + '0') + binary;
		decimal = decimal / 2;
	}
	while (binary.size() < 4)
		binary = '0' + binary;
	return binary;
}


//fucntion to xor plaintext with 48bit key
std::string stringXor(std::string plainText, std::string key){
        
        std::string xorAnswer = "";
        int s = key.size();
        for(int i = 0; i < s; i++){
                if(plainText[i] != key[i]){
                        xorAnswer = xorAnswer + '1';
                }
                else{
                        xorAnswer = xorAnswer + '0';
                }

                }
                return xorAnswer;
        
}

//fucntion to generate the 16 subkeys required for encyption and decyption 
void keyGen(std::string key){

    //64 bit key converted to binary                                                                                                                                                                        
    std::string key_64bits = hexaToBin(key);
    std::cout << "The Key in binary is: " << key_64bits << std::endl;
    std::endl(std::cout);

    //56 bit subkey is convrted into left and right halfs afte PC1 is applied 
    std::string key_56bits = "";
    std::string key_LH = "";
    std::string key_RH = "";

    for (int i = 0; i < 56; i++){
      key_56bits = key_56bits + key_64bits[PC1[i]-1];
    }
    

    for(int i = 0; i < 28; i++){
      key_LH = key_LH + key_56bits[i];
    }

    for(int i = 28; i < 56; i++){
      key_RH = key_RH + key_56bits[i];
    }
    
    //outputting the left and right subkeys before rounds begin 
    std::cout << " The left half of the key (C0): " << key_LH << std::endl;
    std::cout << " The right half of the key (D0): " << key_RH << std::endl;

    //16 rounds of left and right subkey generation stored in these vars 
     std::string sKey_LH[17];
    std::string sKey_RH[17]; 




    
    sKey_LH[0] =key_LH;
    sKey_RH[0] =key_RH;

    //applying the appropriate shifts for each according  and displaying them     
    for(int i = 1; i < 17; i++){
            if (i == 1 || i == 2 || i== 9 || i==16 ){
                    sKey_LH[i] = shiftOnce(sKey_LH[i-1]);
                    sKey_RH[i] = shiftOnce(sKey_RH[i-1]);
                    std::cout << " C" << i << " = " <<sKey_LH[i] << std::endl;
                    std::cout << " D" << i << " = " <<sKey_RH[i] << std::endl;
                    
            }

            else{
                    sKey_LH[i] = ShiftTwice(sKey_LH[i-1]);
                    sKey_RH[i] = ShiftTwice(sKey_RH[i-1]);
                    std::cout << " C" << i << " = " <<sKey_LH[i] << std::endl;
                    std::cout << " D" << i << " = " <<sKey_RH[i] << std::endl;

            }

    }
    
   
    std::string sKey_56bits[16];

    
   for(int i = 0; i < 16; i++){
                    sKey_56bits[i] = sKey_LH[i+1] + sKey_RH[i+1];
            
    }


   for(int i = 0; i < 16; i++){
             sKey_48bits[i] = "";
        for(int j = 0; j < 48; j++){

                sKey_48bits[i] = sKey_48bits[i] + sKey_56bits[i][PC2[j] - 1];
               
        }
        // std::cout << "K" << i+1 << " = " << sKey_48bits[i] << std::endl;
         //std::endl(std::cout);
    }
    

        

}

//function that utilizes all the other fucntion top perform the des algortihm 
//Keygen() uses the global skey_48bit and once called in des() saves the key
//If encyption is performed des() algorithn goes as normal, but if decryption is picked the global skeys_48bit[16] array order is reversed to accomadate 
//then the encyrption algorithm is applied using those subkeys in reversed order 
void des_algo(){

    //getting the user to specify wether they would like to perform decryption or encryption 
    //saving input in acton 
    std::cout << " would you like to perform encryption or decryption (input E to encrypt or D to decrypt) -- ";
    std::string action; 
    std::cin >> action;
    std::endl(std::cout);

    std::string key, pc;
    
    //getting the user to input the ciphertext or plaintext with a Key 
    std::cout << " Enter a 16 character hexadecimal plaintext or cipherText -- ";
    std::cin >> pc;
    std::endl (std::cout);

    std::cout << " Enter a 16 character hexadecimal key -- ";
    std::cin >> key;
    std::endl(std::cout);
    
    //if the key and plaintext/ciphertext size are corrent then continue with the algorithm 
    if(key.size() == 16 || pc.size() == 16 ){
    
    //if user chose encryption then 
    if(action == "e" | action == "E" ){

    keyGen(key);
    //64 bit plaintext converted to binary                                                                                                                                                                  
    std::string plainTextBin = hexaToBin(pc);
    std::cout << " the plaintext in binary is -- " << plainTextBin << std::endl; 
    std::endl(std::cout);

    //initial permutaton stored in Iperm                                                                                                                                                                    
    std::string Iperm = "";

    for(int i = 0; i < 64; i++){
      Iperm = Iperm + plainTextBin[IP[i] - 1];
    }

    // outputting plaintext after intial permutation 
    std::cout << " The plaintext after intial permutaion -- " << Iperm << std::endl;

    std::string plainText_LH = "";
    std::string plainText_RH = "";

    //splitting the plaintext into left and right halfts after initial permuation  has been applied 
    //first half of plaintext is stored in plaintext_lh and the other half is stored in plaintext_rh 
    for(int i = 0; i < 32; i++){
      plainText_LH = plainText_LH + Iperm[i];
    }

    for(int i = 32; i < 64; i++){
      plainText_RH = plainText_RH + Iperm[i];
    }

    //outputting th left and right halfs after the intial perm was applied 
    std::cout << " The left half of plaintext after applying IP is: " << plainText_LH << std::endl;
    std::cout << " The right half of the plaintext after applying IP is " << plainText_RH << std::endl; 
    std::endl(std::cout);

   for(int i=0; i<16; i++) { 
    	std::string RH_48bits = ""; 
        //applying the expansion table to the right half of the plaintext 
    	for(int i = 0; i < 48; i++) { 
      		RH_48bits += plainText_RH[Expansion[i]-1]; 
    };  //xoring the right half of plaintext with the intial subkey produced in that round. 
	std::string RH_XOR_K = stringXor(sKey_48bits[i], RH_48bits);  
		 
        std::string xor_ans= "";
    



   //sbox calculations 
   for(int i=0;i<8; i++){ 
			
      	std::string r1= RH_XOR_K.substr(i*6,1) + RH_XOR_K.substr(i*6 + 5,1);
      	int rows = BinToDec(r1);
      	std::string c1 = RH_XOR_K.substr(i*6 + 1,1) + RH_XOR_K.substr(i*6 + 2,1) + RH_XOR_K.substr(i*6 + 3,1) + RH_XOR_K.substr(i*6 + 4,1);;
	int columns = BinToDec(c1);
	int ans = sBox[i][rows][columns];
	xor_ans+= DecToBin(ans);  
	} 

               

        std::string cipherText_F =""; 
   for(int i = 0; i < 32; i++){ 
	cipherText_F += xor_ans[PermutationF[i]-1]; 
		}

        //xoring of ciphertext and left half 
	RH_XOR_K = stringXor(cipherText_F, plainText_LH);
	//The left and right halfs of the plaintext are then swapped 
	plainText_LH = RH_XOR_K; 
	if(i < 15){ 
		std::string temp2 = plainText_RH;
		plainText_RH = RH_XOR_K;
		plainText_LH = temp2;
		} 
	} 
	//the two halfs of the plaintext are combined again 
	std::string LH_and_RH = plainText_LH + plainText_RH;   
	std::string cipherText_IP =""; 
	// The inverse of the initial permuttaion is applied

   for(int i = 0; i < 64; i++){ 
		cipherText_IP = cipherText_IP + LH_and_RH[IP_inverse[i]-1]; 
	}

   //converting the perumatated binary ciphertext into hexadeciaml value and outputting it
   std::string cipherText_bin = BintoHexa(cipherText_IP);

   std::cout << " The cipherText produced from the given key and plaintext is -- " << cipherText_bin << std::endl;
    }

    else {
        //keyGen is called then while loop is used to reverse the order of array to accomadate for decryption 
        keyGen(key);
        int i = 15;
        int j = 0;

        while(i > j){
                std::string temp2 = sKey_48bits[i];
                sKey_48bits[i] = sKey_48bits[j];
                sKey_48bits[j] = temp2;
                i--;
                j++;                
        }
    
    //the ciphertext is converted to binary 
    //binary cipherText is then displayed 
    std::string cipherTextBin = hexaToBin(pc);
    std::cout << " the ciphertext in binary is: " << cipherTextBin << std::endl; 
    std::endl(std::cout);

    //initial permutaton stored in Iperm                                                                                                                                                                    
    std::string Iperm = "";

    //initial permutation is applied on the ciphertext 
    //iperm holds the result of the intial permutation 
    for(int i = 0; i < 64; i++){
      Iperm = Iperm + cipherTextBin[IP[i] - 1];
    }
    
    //the ciphertext after intial permutation is then displayed
    std::cout << " The ciphertext after initial permuation -- " << Iperm << std::endl;

    std::string cipherText_LH = "";
    std::string cipherText_RH = "";

    //using for loops the ciphertext is split into left and right halfs 
    for(int i = 0; i < 32; i++){
      cipherText_LH = cipherText_LH + Iperm[i];
    }

    for(int i = 32; i < 64; i++){
      cipherText_RH = cipherText_RH + Iperm[i];
    }

    //the left and right halfs of ciphertext are displayed 
    std::cout << " The left half of ciphertext after applying IP is -- " << cipherText_LH << std::endl;
    std::cout << " The right half of the ciphertext after applying IP is -- " << cipherText_RH << std::endl; 
    std::endl(std::cout);

   
   for(int i=0; i<16; i++) { 
    	std::string RH_48bits = ""; 
	//The right half of the cipherText is expanded using the expansion table array 
    	for(int i = 0; i < 48; i++) { 
      		RH_48bits += cipherText_RH[Expansion[i]-1]; 
    };  // The resulis of that then xored with the subkeys and stored in RH_XOR_K 
	std::string RH_XOR_K = stringXor(sKey_48bits[i], RH_48bits);  
		 
        std::string xor_ans= "";
    

   //sbox calculations 
   for(int i=0;i<8; i++){ 
			
      	std::string r1= RH_XOR_K.substr(i*6,1) + RH_XOR_K.substr(i*6 + 5,1);
      	int rows = BinToDec(r1);
      	std::string c1 = RH_XOR_K.substr(i*6 + 1,1) + RH_XOR_K.substr(i*6 + 2,1) + RH_XOR_K.substr(i*6 + 3,1) + RH_XOR_K.substr(i*6 + 4,1);;
	int columns = BinToDec(c1);
	int ans = sBox[i][rows][columns];
	xor_ans+= DecToBin(ans);  
	} 

               
        //the ciphertext then goes through the F fucntion 
        std::string cipherText_F =""; 
   for(int i = 0; i < 32; i++){ 
	cipherText_F += xor_ans[PermutationF[i]-1]; 
		}

	//The answer to that xhored with the LH of the cipherText and stored in RH_XOR_K 
	RH_XOR_K = stringXor(cipherText_F, cipherText_LH);
        //The left and the right halfs oof the ciphertext are then switched   
	cipherText_LH = RH_XOR_K; 
	if(i < 15){ 
		std::string temp2 = cipherText_RH;
		cipherText_RH = RH_XOR_K;
		cipherText_LH = temp2;
		} 
	} 
	//The halves of the cipherText are combined and saved as cipherText_IP
        //then that goes throught he inverse permutation table array 
	std::string LH_and_RH = cipherText_LH + cipherText_RH;   
	std::string cipherText_IP =""; 

   for(int i = 0; i < 64; i++){ 
		cipherText_IP = cipherText_IP + LH_and_RH[IP_inverse[i]-1]; 
	}

   //converting the perumatated binary ciphertext into hexadeciaml value and displaying it
   std::string cipherText_bin = BintoHexa(cipherText_IP);

   std::cout << " The plaintext produced from the given key and plainText is -- " << cipherText_bin << std::endl;

    }
     }

     //else if the hexadeciaml key or plaintext/ciphertext has too many or tooo little characters display an error to user
     else{
             std::cout << " ERROR: The Hexadecimal Plaintext and/or Key has more or less that 16 characters " << std::endl;
     }
}
  

};


//main funciton 
int main(){

        //creating a des object and calling the des algorithm  
        des c;
        c.des_algo();  

        return 0;     

    }
