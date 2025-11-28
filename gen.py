import argparse
import hashlib
import hmac
import binascii
import sys
import os

class IKEv1Generator:
    def __init__(self, traffic_file=None):
        if traffic_file:
            self.load_from_file(traffic_file)
        else:
            self.set_default_values()
    
    def load_from_file(self, filename):
       
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Файл не найден: {filename}")
        
        with open(filename, 'r') as f:
            content = f.read()
        
        data = self.parse_traffic_file(content)
        
        self.Ci = binascii.unhexlify(data.get('Ci', ''))
        self.Ni = binascii.unhexlify(data.get('Ni', ''))
        self.g_x = binascii.unhexlify(data.get('g_x', ''))
        self.Cr = binascii.unhexlify(data.get('Cr', ''))
        self.Nr = binascii.unhexlify(data.get('Nr', ''))
        self.g_y = binascii.unhexlify(data.get('g_y', ''))
        self.SAi = binascii.unhexlify(data.get('SAi', ''))
        self.IDr = binascii.unhexlify(data.get('IDr', ''))
    
    def parse_traffic_file(self, content):
        data = {}

        lines = content.strip().split('\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                data[key] = value  
        
        return data
    
    def set_default_values(self):
        self.Ci = binascii.unhexlify("45b2748cd9ebc86951a53c05beb01731")
        self.Ni = binascii.unhexlify("93fb74129d8dbfe8cb92d4a4757c83b6edf382780e31d158c63aca4a474ada25")
        self.g_x = binascii.unhexlify("ed3c62c7413621d92e4b73eb6a551f445b6fab1810d9b8b6df5470ed2a346133786cf3cab98d87388402bdb345c2fadb9c6e976a491b850af55c2b9c75e23d78e0cfe920d3936c5fbc79d1f7f768001bac6fc7dde87e8a8f47a4c08858db29f469ffc599b1f945c87dab3d78bae6521665102450f6f0442c5a6602b33ad42db6")
        self.Cr = binascii.unhexlify("863fb68d34d266cc55543dbca52b877c")
        self.Nr = binascii.unhexlify("f9060dc0a4dfb896c55f51cf4d3d27a8928d586db5b63522546947669e710825")
        self.g_y = binascii.unhexlify("6afd6501977aa4dccf9c7a09f135af1a300390c314d0bde86817fb224bc01eaa8c1269324abec57f2a4c45f651c5a656c64a97a717e2aeade58d532f6cc25027d6c7062259e2e7ba880970cb283cfe0baa38b4b6152b418878f30ead980aea8a7a2ea743734138cd34b45d09907c460029dce638eb31b39880bd4580a9e91928")
        self.SAi = binascii.unhexlify("4d2d8780e40ff2a842a15efddd577fb0")
        self.IDr = binascii.unhexlify("ab17b82f469dd2e2c91a4cc604408bb9")
        
    def generate_hash(self, password, hash_algorithm):
        
        # SKEYID = prf(password, Ni_b | Nr_b)
        skeyid_input = self.Ni + self.Nr
        
        if hash_algorithm.lower() == 'md5':
            # skeyid = hmac.new(password, Ni|Nr, md5).digest()
            skeyid = hmac.new(password.encode(), skeyid_input, hashlib.md5).digest()
            
            # HASH_R = prf(SKEYID, g_y | g_x | Cr | Ci | SAi | IDr)
            hash_input = self.g_y + self.g_x + self.Cr + self.Ci + self.SAi + self.IDr
            ike_hash = hmac.new(skeyid, hash_input, hashlib.md5).digest()
            
        elif hash_algorithm.lower() == 'sha1':
            skeyid = hmac.new(password.encode(), skeyid_input, hashlib.sha1).digest()
            hash_input = self.g_y + self.g_x + self.Cr + self.Ci + self.SAi + self.IDr
            ike_hash = hmac.new(skeyid, hash_input, hashlib.sha1).digest()
        else:
            raise ValueError(f"Алгоритм не поддерживается: {hash_algorithm}")
            
        return ike_hash
    
    def generate_test_data(self, password, hash_algorithm):
        ike_hash = self.generate_hash(password, hash_algorithm)
        
        result = f"{binascii.hexlify(self.Ni).decode()}*{binascii.hexlify(self.Nr).decode()}*{binascii.hexlify(self.g_x).decode()}*{binascii.hexlify(self.g_y).decode()}*{binascii.hexlify(self.Ci).decode()}*{binascii.hexlify(self.Cr).decode()}*{binascii.hexlify(self.SAi).decode()}*{binascii.hexlify(self.IDr).decode()}*{binascii.hexlify(ike_hash).decode()}"
        
        return result

def main():
    parser = argparse.ArgumentParser(description='IKEv1 Aggressive Mode Test Data Generator')
    parser.add_argument('-m', '--mode', required=True, choices=['md5', 'sha1'], 
                       help='Hash algorithm (md5 or sha1)')
    parser.add_argument('-p', '--password', required=True, 
                       help='Password to generate test data')
    parser.add_argument('-f', '--file', 
                       help='Traffic file with IKE data')
    parser.add_argument('-o', '--output', 
                       help='Output file to save results')
    
    args = parser.parse_args()
    
    try:
        generator = IKEv1Generator(args.file)
        test_data = generator.generate_test_data(args.password, args.mode)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(test_data)
            print(f"Test data сохранен в: {args.output}")
        else:
            print(test_data)
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":

    main()
