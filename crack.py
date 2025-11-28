import hashlib
import sys
import binascii
import multiprocessing as mp
from itertools import product, islice
import time
import argparse
import hmac
from datetime import datetime

def init_worker(mask, ike_params):
   
    global MASK, TARGET_HASH, HASH_ALGORITHM, IKE_VALUES
    MASK = mask
    TARGET_HASH = binascii.unhexlify(ike_params['HASH'])
    HASH_ALGORITHM = ike_params['hash_algorithm']
    IKE_VALUES = {
        'Ci': binascii.unhexlify(ike_params['Ci']),
        'Ni': binascii.unhexlify(ike_params['Ni']),
        'g_x': binascii.unhexlify(ike_params['g_x']),
        'Cr': binascii.unhexlify(ike_params['Cr']),
        'Nr': binascii.unhexlify(ike_params['Nr']),
        'g_y': binascii.unhexlify(ike_params['g_y']),
        'SAi': binascii.unhexlify(ike_params['SAi']),
        'IDr': binascii.unhexlify(ike_params['IDr'])
    }

def worker_process(chunk_args):
    start_idx, chunk_size = chunk_args
    
    char_sets = {
        'a': "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        'd': "0123456789", 
        'l': "abcdefghijklmnopqrstuvwxyz",
        'u': "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    }
    
    alphabets = [char_sets[char] for char in MASK]
    
    # пароли для чанка
    count = 0
    passwords = islice(product(*alphabets), start_idx, start_idx + chunk_size)
    
    for password_chars in passwords:
        password = ''.join(password_chars)
        count += 1
        
        try:
            # SKEYID = prf(password, Ni | Nr)
            if HASH_ALGORITHM == 'md5':
                skeyid = hmac.new(password.encode(), IKE_VALUES['Ni'] + IKE_VALUES['Nr'], hashlib.md5).digest()
            else:
                skeyid = hmac.new(password.encode(), IKE_VALUES['Ni'] + IKE_VALUES['Nr'], hashlib.sha1).digest()
            
            # HASH_R = prf(SKEYID, g_y | g_x | Cr | Ci | SAi | IDr)
            data = (IKE_VALUES['g_y'] + IKE_VALUES['g_x'] + IKE_VALUES['Cr'] + 
                   IKE_VALUES['Ci'] + IKE_VALUES['SAi'] + IKE_VALUES['IDr'])
            
            if HASH_ALGORITHM == 'md5':
                hash_r = hmac.new(skeyid, data, hashlib.md5).digest()
            else:
                hash_r = hmac.new(skeyid, data, hashlib.sha1).digest()
            
            if hash_r == TARGET_HASH:
                return ('found', password, count)
                
        except Exception:
            continue
    
    return ('done', None, count)

def parse_input_data(test_data):
    params = {}
    
    if '*' in test_data:
        parts = test_data.strip().split('*')
        if len(parts) == 9:
            params['Ni'] = parts[0]
            params['Nr'] = parts[1]
            params['g_x'] = parts[2]
            params['g_y'] = parts[3]
            params['Ci'] = parts[4]
            params['Cr'] = parts[5]
            params['SAi'] = parts[6]
            params['IDr'] = parts[7]
            params['HASH'] = parts[8]
            return params
    
    # Формат с разделителем :
    lines = test_data.strip().split('\n')
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            params[key.strip()] = value.strip()
    
    return params

def crack_parallel(mask, test_data, num_processes=None):
    #параллелим
    print("\nЗапуск параллельного перебора...")
    
    params = parse_input_data(test_data)
    
    target_hash = binascii.unhexlify(params['HASH'])
    hash_size = len(target_hash)
    if hash_size == 16:
        hash_algorithm = 'md5'
        print("Обнаружен алгоритм: MD5 (16 байт)")
    elif hash_size == 20:
        hash_algorithm = 'sha1'
        print("Обнаружен алгоритм: SHA1 (20 байт)")
    else:
        hash_algorithm = 'md5'
        print("Используется MD5 по умолчанию")
    
    params['hash_algorithm'] = hash_algorithm
    
    char_sets = {
        'a': "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        'd': "0123456789", 
        'l': "abcdefghijklmnopqrstuvwxyz",
        'u': "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    }
    
    #Количество паролей для перебора
    alphabets = [char_sets[char] for char in mask]
    total_combinations = 1
    for alphabet in alphabets:
        total_combinations *= len(alphabet)
    
    print(f"Параметры перебора:")
    print(f"   Маска: {mask}")
    print(f"   Длина пароля: {len(mask)}")
    print(f"   Алгоритм: {hash_algorithm.upper()}")
    print(f"   Размер хеша: {hash_size} байт")
    print(f"   Всего комбинаций: {total_combinations:,}")
    
    #Настройка процессов
    if num_processes is None:
        num_processes = mp.cpu_count()
    else:
        num_processes = min(num_processes, mp.cpu_count())
    
    print(f"Используется процессов: {num_processes}")
    print("-" * 60)
    
    start_time = datetime.now()
    found_password = None
    total_processed = 0
    completed_chunks = 0
    
    chunk_size = 50000
    chunks = []
    for start in range(0, total_combinations, chunk_size):
        end = min(start + chunk_size, total_combinations)
        chunks.append((start, end - start))
    
    
    # пул процессов
    with mp.Pool(processes=num_processes, initializer=init_worker, initargs=(mask, params)) as pool:
        results = pool.imap_unordered(worker_process, chunks)
        
        for result in results:
            msg_type, data, count = result
            completed_chunks += 1
            total_processed += count
            
            if msg_type == 'found':
                found_password = data
                print(f"\nПаРоЛь НАЙДЕН: {found_password}")
                pool.terminate()
                break
            
            # Прогресс
            current_time = datetime.now()
            elapsed = (current_time - start_time).total_seconds()
            percent = (total_processed / total_combinations) * 100
            speed = total_processed / elapsed if elapsed > 0 else 0
            
            if speed > 0:
                remaining = (total_combinations - total_processed) / speed
                if remaining > 3600:
                    eta = f"{remaining/3600:.1f}ч"
                elif remaining > 60:
                    eta = f"{remaining/60:.1f}м"
                else:
                    eta = f"{remaining:.0f}с"
            else:
                eta = "00"
            
            progress_bar = '#' * int(percent / 2) + '-' * (50 - int(percent / 2))
            print(f"\r[{progress_bar}] {percent:5.1f}% | {total_processed:,}/{total_combinations:,} | {speed:,.0f} пар/с | Осталось: {eta}", end='', flush=True)
    
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\nВремя выполнения: {elapsed:.2f} секунд")
    if elapsed > 0:
        print(f"Средняя скорость: {total_processed/elapsed:,.0f} паролей/сек")
    
    if found_password:
        # Проверяем пароль 
        if hash_algorithm == 'md5':
            skeyid = hmac.new(found_password.encode(), binascii.unhexlify(params['Ni']) + binascii.unhexlify(params['Nr']), hashlib.md5).digest()
            data = (binascii.unhexlify(params['g_y']) + binascii.unhexlify(params['g_x']) + 
                   binascii.unhexlify(params['Cr']) + binascii.unhexlify(params['Ci']) + 
                   binascii.unhexlify(params['SAi']) + binascii.unhexlify(params['IDr']))
            test_hash = hmac.new(skeyid, data, hashlib.md5).digest()
        else:
            skeyid = hmac.new(found_password.encode(), binascii.unhexlify(params['Ni']) + binascii.unhexlify(params['Nr']), hashlib.sha1).digest()
            data = (binascii.unhexlify(params['g_y']) + binascii.unhexlify(params['g_x']) + 
                   binascii.unhexlify(params['Cr']) + binascii.unhexlify(params['Ci']) + 
                   binascii.unhexlify(params['SAi']) + binascii.unhexlify(params['IDr']))
            test_hash = hmac.new(skeyid, data, hashlib.sha1).digest()
        
        if test_hash == target_hash:
            print("Пароль верифицирован успешно")
        return found_password
    
    print("\nПароль не найден")
    return None

def main():
    parser = argparse.ArgumentParser(description='IKEv1 Password Cracker')
    parser.add_argument('-m', '--mask', required=True, 
                       help='Password mask (a=alphanumeric, d=digits, l=lowercase, u=uppercase)')
    parser.add_argument('-p', '--processes', type=int, 
                       help='Number of processes to use (default: all CPU cores)')
    parser.add_argument('test_file', nargs='?', help='File with test data')
    
    args = parser.parse_args()
    
    # Данные по умолчанию
    if args.test_file:
        with open(args.test_file, 'r') as f:
            test_data = f.read()
    else:
        test_data = """Ci: 45b2748cd9ebc86951a53c05beb01731
Ni: 93fb74129d8dbfe8cb92d4a4757c83b6edf382780e31d158c63aca4a474ada25
g_x: ed3c62c7413621d92e4b73eb6a551f445b6fab1810d9b8b6df5470ed2a346133786cf3cab98d87388402bdb345c2fadb9c6e976a491b850af55c2b9c75e23d78e0cfe920d3936c5fbc79d1f7f768001bac6fc7dde87e8a8f47a4c08858db29f469ffc599b1f945c87dab3d78bae6521665102450f6f0442c5a6602b33ad42db6
Cr: 863fb68d34d266cc55543dbca52b877c
Nr: f9060dc0a4dfb896c55f51cf4d3d27a8928d586db5b63522546947669e710825
g_y: 6afd6501977aa4dccf9c7a09f135af1a300390c314d0bde86817fb224bc01eaa8c1269324abec57f2a4c45f651c5a656c64a97a717e2aeade58d532f6cc25027d6c7062259e2e7ba880970cb283cfe0baa38b4b6152b418878f30ead980aea8a7a2ea743734138cd34b45d09907c460029dce638eb31b39880bd4580a9e91928
SAi: 4d2d8780e40ff2a842a15efddd577fb0
IDr: ab17b82f469dd2e2c91a4cc604408bb9
HASH: 01ce01496bff79585d55da9c951328dd"""
    
    result = crack_parallel(args.mask, test_data, args.processes)
    
    if result:
        print(f"\nНашли пароль: {result}")
    else:
        print(f"\nПароль не найден для маски: {args.mask}")

if __name__ == "__main__":
    main()