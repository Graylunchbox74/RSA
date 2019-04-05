#include "Infint/InfInt.h"

namespace Security{
static const InfInt MAX_RANDOM_NUMBER = "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const InfInt MIN_RANDOM_NUMBER = "1000000000000000000000000000000000000000000000000000";

	static InfInt random_number();
	static InfInt Generate_Random_Prime();
	static bool fermat_primality_test(InfInt test_value);
	static bool miller_rabin_primality_test(InfInt test_value);
	static InfInt euclidean_gcd(InfInt first_value, InfInt second_value);
	static InfInt extended_euclidean_inverse(InfInt value, InfInt mod);
	static InfInt power_mod(InfInt base, InfInt power, InfInt mod);

	struct RSA_Public_Key{
		InfInt encrypt_power;
		InfInt mod;
		unsigned int padding;
	};

	struct RSA_Private_Key{
		InfInt prime_1, prime_2;
		InfInt encrypt_power;
		InfInt decrypt_power;
		InfInt mod;
	};

	std::string Add_Padding(InfInt data, RSA_Public_Key key)
	{
		std::string data_string = data.toString();
		while (data_string.length() < key.padding)
		{
			data_string = "0" + data_string;
		}
		return data_string;
	}

	RSA_Private_Key Generate_RSA_Private_Key()
	{
		RSA_Private_Key gen_key;
		gen_key.prime_1 = Generate_Random_Prime();
		gen_key.prime_2 = Generate_Random_Prime();
		gen_key.mod = gen_key.prime_1 * gen_key.prime_2;
		InfInt tmp = random_number() % ((gen_key.prime_1 - 1)*(gen_key.prime_2-1) - MIN_RANDOM_NUMBER) + MIN_RANDOM_NUMBER;
		while (euclidean_gcd(tmp, (gen_key.prime_1 - 1)*(gen_key.prime_2-1)) != 1)
		{
			tmp = random_number() % ((gen_key.prime_1 - 1)*(gen_key.prime_2-1) - MIN_RANDOM_NUMBER) + MIN_RANDOM_NUMBER;
		}
		gen_key.encrypt_power = tmp;
		gen_key.decrypt_power = extended_euclidean_inverse(gen_key.encrypt_power, (gen_key.prime_1 - 1)*(gen_key.prime_2-1));
		return gen_key;
	}

	RSA_Public_Key Generate_RSA_Public_Key(RSA_Private_Key& private_key)
	{
		RSA_Public_Key gen_key;
		gen_key.encrypt_power = private_key.encrypt_power;
		gen_key.mod = private_key.mod;
		gen_key.padding = gen_key.mod.numberOfDigits();
		return gen_key;
	}

	//RSA Encrypting functions
	InfInt RSA_Encrypt_Data(InfInt data, RSA_Public_Key& key)
	{
		return power_mod(data, key.encrypt_power, key.mod);
	}

	InfInt RSA_Encrypt_Data(unsigned long data, RSA_Public_Key& key)
	{
		return power_mod((InfInt)data, key.encrypt_power, key.mod);
	}

	InfInt RSA_Encrypt_Data(unsigned int data, RSA_Public_Key& key)
	{
		return power_mod(InfInt(data), key.encrypt_power, key.mod);
	}

	std::vector<InfInt> RSA_Encrypt_Data(std::vector<InfInt> data, RSA_Public_Key& key)
	{
		std::vector<InfInt> encrypted_data;
		for (unsigned long i = 0; i < data.size(); i++)
			encrypted_data.push_back(RSA_Encrypt_Data(data[i],key));
		return encrypted_data;
	}

	std::vector<InfInt> RSA_Encrypt_Data(std::vector<unsigned long long> data, RSA_Public_Key& key)
	{
		std::vector<InfInt> encrypted_data;
		for (unsigned long i = 0; i < data.size(); i++)
			encrypted_data.push_back(RSA_Encrypt_Data((InfInt)data[i],key));
		return encrypted_data;
	}

	std::vector<InfInt> RSA_Encrypt_Data(std::vector<unsigned long> data, RSA_Public_Key& key)
	{
		std::vector<InfInt> encrypted_data;
		for (unsigned long i = 0; i < data.size(); i++)
			encrypted_data.push_back(RSA_Encrypt_Data((InfInt)data[i],key));
		return encrypted_data;
	}

	std::vector<InfInt> RSA_Encrypt_Data(std::vector<unsigned int> data, RSA_Public_Key& key)
	{
		std::vector<InfInt> encrypted_data;
		for (unsigned long i = 0; i < data.size(); i++)
			encrypted_data.push_back(RSA_Encrypt_Data((InfInt)data[i],key));
		return encrypted_data;
	}

	std::vector<InfInt> RSA_Encrypt_Data(std::string data, RSA_Public_Key& key)
	{
		std::vector<InfInt> encrypted_data;
		InfInt tmp;

		for (unsigned long i; i < data.length(); i++)
		{
			tmp = (InfInt)((int)data[i]);
			encrypted_data.push_back(RSA_Encrypt_Data(tmp, key));
		}

		return encrypted_data;
	}

	std::vector<std::vector<InfInt> > RSA_Encrypt_Data(std::vector<std::string> data, RSA_Public_Key& key)
	{
		std::vector<std::vector<InfInt> > encrypted_data;
		for (unsigned int i = 0; i < data.size(); i++)
		{
			encrypted_data.push_back(RSA_Encrypt_Data(data[i], key));
		}
		return encrypted_data;
	}

	//RSA Decrypting functions
	InfInt RSA_Decrypt_Data(InfInt data, RSA_Private_Key& key)
	{
		return power_mod(data, key.decrypt_power, key.mod);
	}

	std::string RSA_Decrypt_Data(std::vector<InfInt> data, RSA_Private_Key& key)
	{
		std::vector<InfInt> decrypted_data;
		for (unsigned long i = 0; i < data.size(); i++)
			decrypted_data.push_back(RSA_Decrypt_Data(data[i],key));

		std::string decrypted_string;
		for (unsigned long i = 0; i < decrypted_data.size(); i++)
		{
			decrypted_string.push_back((char)(decrypted_data[i].toInt()));
		}

		return decrypted_string;
	}

	std::string RSA_Decrypt_Data(std::vector<std::string> data, RSA_Private_Key& key)
	{
		std::string decrypted_string;
		for (unsigned long i = 0; i < data.size(); i++)
		{
			decrypted_string.push_back((char)(RSA_Decrypt_Data((InfInt)data[i],key).toInt()));
		}
		return decrypted_string;
	}

	//utility functions
	static InfInt Generate_Random_Prime()
	{
		std::vector<InfInt> tested_numbers;
		tested_numbers.push_back(random_number() % (MAX_RANDOM_NUMBER - 3) + 3);
		while (tested_numbers[tested_numbers.size() - 1] % 2 == 0 ||
		 fermat_primality_test(tested_numbers[tested_numbers.size() - 1]) == false ||
		  miller_rabin_primality_test(tested_numbers[tested_numbers.size() - 1]) == false)
		{
			InfInt tmp;
			tmp = random_number() % (MAX_RANDOM_NUMBER - MIN_RANDOM_NUMBER) + MIN_RANDOM_NUMBER;
			while (std::find(tested_numbers.begin(), tested_numbers.end(), tmp) != tested_numbers.end())
			{
				tmp = random_number() % (MAX_RANDOM_NUMBER - MIN_RANDOM_NUMBER) + MIN_RANDOM_NUMBER;
			}
			tested_numbers.push_back(tmp);
			std::cout << tested_numbers[tested_numbers.size() - 1] << std::endl;
		}
		return tested_numbers[tested_numbers.size() - 1];
	}

	static InfInt random_number()
	{
		std::string random = "";
		unsigned int dig = rand();
		for (unsigned int i = 0; i < MIN_RANDOM_NUMBER.numberOfDigits() + (dig % (MAX_RANDOM_NUMBER - MIN_RANDOM_NUMBER).numberOfDigits()); i++)
		{
			random.push_back((rand() % 10) + '0');
		}
		InfInt num(random);
		num %= (MAX_RANDOM_NUMBER - MIN_RANDOM_NUMBER);
		//num += MIN_RANDOM_NUMBER;
		return num;
	}

	static bool fermat_primality_test(InfInt test_value)
	{
		if (power_mod(2, test_value - 1, test_value) != 1)
			return false;
		return true;
	}

	static bool miller_rabin_witness(InfInt test_value, InfInt witness)
	{
		InfInt q = test_value - 1;
		InfInt k = 0;
		while (q % 2  == 0)
		{
			k++;
			q = q / 2;
		}
		witness = power_mod(witness, q, test_value);
		if (witness == 1 || witness == test_value - 1)
		{
			return false; //not a witness
		}
		for (InfInt i = 0; i < k-1; i++)
		{
			if (witness % test_value == witness - 1)
			{
				return false; //not a witness
			}
			witness = power_mod(witness, 2, test_value);
		}
		return true; //is a witness and n is composite
	}

	static bool miller_rabin_primality_test(InfInt test_value)
	{
		std::vector<InfInt> tested_values;

		for (int i = 0; i < 10; i++)
		{
			if((InfInt)tested_values.size() >= test_value - 3)
				break;

			InfInt tmp = random_number() % (test_value - 2) + 2;
			while (std::find(tested_values.begin(), tested_values.end(), tmp) != tested_values.end())
			{
				tmp = random_number() % (test_value - 3) + 2;
			}
			tested_values.push_back(tmp);

			//std::cout << tmp << std::endl;

			if (miller_rabin_witness(test_value, tested_values[tested_values.size() - 1]) == true)
			{
				return false; //number is certainly composite
			}
		}
		return true; //we probably got a prime! :)
	}

	static InfInt euclidean_gcd(InfInt first_value, InfInt second_value)
	{
		InfInt divisor, dividend, remainder, quotient;
		if (first_value > second_value)
		{
			divisor = first_value;
			dividend = second_value;
		}
		else if (second_value > first_value)
		{
			divisor = second_value;
			dividend = first_value;
		}
		else
		{
			return first_value;
		}
		quotient = divisor / dividend;
		remainder = divisor % dividend;
		InfInt previous_remainder = remainder;
		while (remainder != 0)
		{
			previous_remainder = remainder;
			divisor = dividend;
			dividend = remainder;
			quotient = divisor / dividend;
			remainder = divisor % dividend;
		}
		return previous_remainder;
	}

	static InfInt extended_euclidean_inverse(InfInt value, InfInt mod)
	{
	    InfInt u = 1;
	    InfInt g = value;
	    InfInt x = 0;
	    InfInt y = mod;
		while (y != 0)
		{
	        InfInt q = g / y;
	        InfInt t = g % y;
	        InfInt s = u - q * x;
	        u = x;
	        g = y;
	        x = s;
	        y = t;
	    }
	    if (u > 0)
	     {
	     	return (InfInt)u;
	     }
	    else
	    {
	        while (u < 0)
	        {
	            u += mod/g;
	        }
	    	return (InfInt)u;
	    }
	}

	static InfInt power_mod(InfInt base, InfInt power, InfInt mod)
	{
		InfInt a = base;
		InfInt b = 1;
		while (power > 0)
		{
			if (power % 2 == 1)
			{
				b = (b * a) % mod;
			}
			a = (a * a) % mod;
			power = power / 2;
		}
		return b;
	}
};


int main(){
	srand(time(NULL));
	Security::RSA_Private_Key key = Security::Generate_RSA_Private_Key();
	Security::RSA_Public_Key pkey = Security::Generate_RSA_Public_Key(key);
	std::cout << "p: " << key.prime_1 << std::endl;
	std::cout << "q: " << key.prime_2 << std::endl;
	std::cout << "N: " << key.mod << std::endl;
	std::cout << "e: " << key.encrypt_power << std::endl;
	std::cout << "d: " << key.decrypt_power <<std::endl;
	unsigned int data = 1337;
	InfInt edata;
	edata = Security::RSA_Encrypt_Data(data, pkey);
	std::cout << "Encrypted: " << edata << std::endl;
	edata = Security::RSA_Decrypt_Data(edata, key);
	std::cout << "Decrypted: " << edata << std::endl;
	std::string newdata = "1337";
	std::vector<InfInt> newedata = Security::RSA_Encrypt_Data(newdata, pkey);
	std::vector<std::string> newsdata;
	for (int i = 0; i < newedata.size(); i++)
	{
		newsdata.push_back(Add_Padding(newedata[i],pkey));
		std::cout << i << ": Encrypted: " << Add_Padding(newedata[i],pkey) << std::endl;		
	}
	newdata = Security::RSA_Decrypt_Data(newedata, key);
	std::cout << "Decrypted: " << newdata << std::endl;
	std::cout << "Decrypted: " << Security::RSA_Decrypt_Data(newsdata,key) << std::endl;


}