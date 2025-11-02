import os
import sys
import time
import gc
import argparse
import secrets
from pathlib import Path
import psutil
from tqdm import tqdm
import pandas as pd
import matplotlib.pyplot as plt
from typing import Optional, Any

# --- Імпорти Cryptography ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding # Симетричний падінг
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding # Асиметричний падінг
from cryptography.hazmat.backends import default_backend

# --- Налаштування шляхів ---
# Визначаємо шлях до поточної директорії (корінь проєкту)
SCRIPT_DIR = Path(__file__).parent.resolve()
# Визначаємо вихідну директорію (benchmarks/encryption_tests)
OUTPUT_DIR = SCRIPT_DIR / "benchmarks" / "encryption_tests"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True) # Створюємо папку, якщо її немає

# --- Глобальні налаштування бенчмарку ---
DEFAULT_SIZES = [1 * 1024, 10 * 1024, 100 * 1024, 1 * 1024 * 1024] # 1KB, 10KB, 100KB, 1MB
DEFAULT_ITERATIONS = 10
RSA_KEY_SIZE_BITS = 2048
AES_KEY_SIZE_BYTES = 32 # 256-біт (32 байти)

# Процес для моніторингу пам'яті
_process = psutil.Process(os.getpid())

# --- Допоміжні функції ---

def measure_time_and_memory(func: Any, *args, **kwargs) -> tuple[Any, float, int]:
    """
    Вимірює час виконання (в секундах) та зміну RSS пам'яті (в байтах).
    Повертає: (результат_функції, час_виконання, зміна_памяті)
    """
    gc.collect() # Збираємо сміття перед виміром
    mem_before = _process.memory_info().rss
    t_start = time.perf_counter()
    
    result = func(*args, **kwargs) # Виклик цільової функції
    
    t_end = time.perf_counter()
    gc.collect() # Збираємо сміття після виміру
    mem_after = _process.memory_info().rss
    
    return result, (t_end - t_start), (mem_after - mem_before)

def bytes_to_human(n: float | int) -> str:
    """
    Форматує байти у читабельний вигляд (KB, MB...).
    """
    n_val = float(n)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n_val < 1024.0:
            return f"{n_val:.2f} {unit}"
        n_val /= 1024.0
    return f"{n_val:.2f} TB"

# --- Реалізація криптографії ---

# --- AES-CBC (для порівняння з C# реалізацією) ---
def aes_cbc_generate_key() -> bytes:
    """Генерує 32-байтний (256-біт) ключ AES."""
    return secrets.token_bytes(AES_KEY_SIZE_BYTES)

def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Шифрує дані за допомогою AES-CBC-256 з PKCS7-падінгом.
    (Відповідає реалізації в C#).
    Повертає (iv, ciphertext).
    """
    iv = secrets.token_bytes(16) # Стандартний розмір блоку AES (128 біт)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Додаємо падінг PKCS7
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Розшифровує дані AES-CBC-256 та знімає PKCS7-падінг.
    (Відповідає реалізації в C#).
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Знімаємо падінг PKCS7
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

# --- AES-GCM (сучасний стандарт AEAD для порівняння) ---
def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Шифрує дані за допомогою AES-GCM-256 (стандарт AEAD).
    Повертає (nonce, ciphertext). Nonce (12 байт) потрібен для дешифрування.
    """
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12) # GCM зазвичай використовує 12-байтний nonce
    # Tag аутентифікації (16 байт) автоматично додається в кінець ciphertext
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None) 
    return nonce, ciphertext

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Розшифровує дані AES-GCM-256 та перевіряє тег аутентифікації."""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext

# --- RSA-OAEP (для гібридної схеми) ---
def rsa_generate_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Генерує пару RSA ключів (2048 біт)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=RSA_KEY_SIZE_BITS,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def rsa_encrypt_oaep(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """Шифрує дані (зазвичай сесійний ключ) за допомогою RSA-OAEP з SHA-256."""
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_oaep(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Розшифровує дані RSA-OAEP з SHA-256."""
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# --- Гібридна схема (RSA-OAEP + AES-CBC) ---
def hybrid_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> dict[str, bytes]:
    """
    Гібридне шифрування (відповідає реалізації C#).
    1. Генерує сесійний AES-ключ.
    2. Шифрує дані за допомогою AES-CBC (aes_cbc_encrypt).
    3. Шифрує сесійний AES-ключ за допомогою RSA-OAEP (rsa_encrypt_oaep).
    """
    session_key = aes_cbc_generate_key()
    iv, encrypted_data = aes_cbc_encrypt(session_key, plaintext)
    encrypted_key = rsa_encrypt_oaep(public_key, session_key)
    
    return {
        "encrypted_key": encrypted_key,
        "iv": iv,
        "ciphertext": encrypted_data,
    }

def hybrid_decrypt(private_key: rsa.RSAPrivateKey, package: dict[str, bytes]) -> bytes:
    """
    Гібридне дешифрування (відповідає реалізації C#).
    """
    session_key = rsa_decrypt_oaep(private_key, package["encrypted_key"])
    plaintext = aes_cbc_decrypt(session_key, package["iv"], package["ciphertext"])
    return plaintext

# --- Логіка бенчмарку ---

def run_benchmarks(test_sizes: list[int], iterations: int) -> pd.DataFrame:
    """
    Запускає тести шифрування/дешифрування для трьох методів:
    1. AES-GCM-256 (сучасний стандарт AEAD)
    2. AES-CBC-256 (аналог реалізації в C#)
    3. RSA-Hybrid (аналог реалізації в C#)
    """
    results: list[dict[str, Any]] = []
    
    print(f"Генеруємо пару RSA ключів ({RSA_KEY_SIZE_BITS}-біт)...")
    rsa_private_key, rsa_public_key = rsa_generate_keypair()

    for size in test_sizes:
        print(f"\nТестування розміру: {bytes_to_human(size)} (Ітерацій: {iterations})")
        
        for i in tqdm(range(iterations), desc=f"Розмір {bytes_to_human(size)}", leave=False):
            # Генеруємо унікальні дані для кожної ітерації
            plaintext = secrets.token_bytes(size)
            # Використовуємо однаковий ключ для AES-GCM та AES-CBC для чистоти порівняння
            aes_key = aes_cbc_generate_key() 
            
            # --- Тест 1: AES-GCM-256 ---
            try:
                # ВИПРАВЛЕНО: Зберігаємо результат (nonce, ct) з першого вимірюваного виклику
                (gcm_nonce, gcm_ct), enc_time_gcm, enc_mem_gcm = measure_time_and_memory(aes_gcm_encrypt, aes_key, plaintext)
                _, dec_time_gcm, dec_mem_gcm = measure_time_and_memory(aes_gcm_decrypt, aes_key, gcm_nonce, gcm_ct)
                results.append({'method': 'AES-GCM-256', 'size_bytes': size, 'operation': 'encrypt', 'time_sec': enc_time_gcm, 'mem_delta_bytes': enc_mem_gcm})
                results.append({'method': 'AES-GCM-256', 'size_bytes': size, 'operation': 'decrypt', 'time_sec': dec_time_gcm, 'mem_delta_bytes': dec_mem_gcm})
            except Exception as e:
                print(f"Помилка AES-GCM: {e}", file=sys.stderr)

            # --- Тест 2: AES-CBC-256 (як у C#) ---
            try:
                # ВИПРАВЛЕНО: Зберігаємо результат (iv, ct) з першого вимірюваного виклику
                (cbc_iv, cbc_ct), enc_time_cbc, enc_mem_cbc = measure_time_and_memory(aes_cbc_encrypt, aes_key, plaintext)
                _, dec_time_cbc, dec_mem_cbc = measure_time_and_memory(aes_cbc_decrypt, aes_key, cbc_iv, cbc_ct)
                results.append({'method': 'AES-CBC-256', 'size_bytes': size, 'operation': 'encrypt', 'time_sec': enc_time_cbc, 'mem_delta_bytes': enc_mem_cbc})
                results.append({'method': 'AES-CBC-256', 'size_bytes': size, 'operation': 'decrypt', 'time_sec': dec_time_cbc, 'mem_delta_bytes': dec_mem_cbc})
            except Exception as e:
                print(f"Помилка AES-CBC: {e}", file=sys.stderr)

            # --- Тест 3: RSA-Hybrid (як у C#) ---
            try:
                # ВИПРАВЛЕНО: Зберігаємо результат (hybrid_pkg) з першого вимірюваного виклику
                hybrid_pkg, enc_time_hyb, enc_mem_hyb = measure_time_and_memory(hybrid_encrypt, rsa_public_key, plaintext)
                _, dec_time_hyb, dec_mem_hyb = measure_time_and_memory(hybrid_decrypt, rsa_private_key, hybrid_pkg)
                results.append({'method': f'RSA-Hybrid (RSA-{RSA_KEY_SIZE_BITS} + AES-256-CBC)', 'size_bytes': size, 'operation': 'encrypt', 'time_sec': enc_time_hyb, 'mem_delta_bytes': enc_mem_hyb})
                results.append({'method': f'RSA-Hybrid (RSA-{RSA_KEY_SIZE_BITS} + AES-256-CBC)', 'size_bytes': size, 'operation': 'decrypt', 'time_sec': dec_time_hyb, 'mem_delta_bytes': dec_mem_hyb})
            except Exception as e:
                print(f"Помилка RSA-Hybrid: {e}", file=sys.stderr)

    df = pd.DataFrame(results)
    out_csv = OUTPUT_DIR / "aes_vs_rsa_results.csv"
    df.to_csv(out_csv, index=False)
    print(f"\nРезультати збережено: {out_csv.relative_to(SCRIPT_DIR.parent)}")
    return df

# --- Візуалізація ---

def summarize_and_plot(df: pd.DataFrame):
    """
    Агрегує дані та будує графіки часу та пам'яті.
    """
    if df.empty:
        print("DataFrame порожній, пропуск візуалізації.")
        return pd.DataFrame()
        
    # Агрегуємо середні значення для кожного методу, розміру та операції
    df_summary = df.groupby(['method', 'size_bytes', 'operation']).agg(
        mean_time_sec=('time_sec', 'mean'),
        mean_mem_bytes=('mem_delta_bytes', 'mean'),
    ).reset_index()
    
    # Збереження зведеної таблиці
    csv_summary = OUTPUT_DIR / "aes_vs_rsa_summary.csv"
    df_summary.to_csv(csv_summary, index=False)
    print(f"Зведена таблиця збережена: {csv_summary.relative_to(SCRIPT_DIR.parent)}")

    # Побудова графіків часу (шифрування та дешифрування окремо)
    for operation in ['encrypt', 'decrypt']:
        op_title = "Шифрування" if operation == 'encrypt' else "Розшифрування"
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        df_op = df_summary[df_summary['operation'] == operation]
        if df_op.empty:
            print(f"Немає даних для графіку '{op_title}'.")
            plt.close(fig)
            continue
            
        for method, group in df_op.groupby('method'):
            ax.plot(group['size_bytes'], group['mean_time_sec'] * 1000, marker='o', label=method) # в мілісекундах
            
        ax.set_xscale('log') # Логарифмічна шкала для розміру
        ax.set_yscale('log') # Логарифмічна шкала для часу
        ax.set_xlabel('Розмір даних (байти, лог. шкала)')
        ax.set_ylabel('Середній час (мілісекунди, лог. шкала)')
        ax.set_title(f'Продуктивність: {op_title}')
        ax.legend()
        ax.grid(True, which='both', ls='--', lw=0.5)
        
        png_file = OUTPUT_DIR / f'aes_vs_rsa_time_{operation}_ms.png'
        fig.tight_layout()
        fig.savefig(str(png_file))
        print(f"Графік часу збережено: {png_file.relative_to(SCRIPT_DIR.parent)}")
        plt.close(fig)

    # (Опціонально) Графік пам'яті
    fig, ax = plt.subplots(figsize=(10, 6))
    # Беремо середнє між шифруванням та дешифруванням для пам'яті
    mem_mean_df = df_summary.groupby(['method', 'size_bytes'])['mean_mem_bytes'].mean().reset_index()
    
    if mem_mean_df.empty:
        print("Немає даних для графіку пам'яті.")
        plt.close(fig)
        return df_summary # Повертаємо зведену таблицю, що була створена

    for method, group in mem_mean_df.groupby('method'):
        ax.plot(group['size_bytes'], group['mean_mem_bytes'], marker='o', label=method)
        
    ax.set_xscale('log')
    ax.set_xlabel('Розмір даних (байти, лог. шкала)')
    ax.set_ylabel('Середня зміна RSS пам\'яті (байти)')
    ax.set_title('Використання пам\'яті (Середнє)')
    ax.legend()
    ax.grid(True, which='both', ls='--', lw=0.5)
    png_file = OUTPUT_DIR / 'aes_vs_rsa_memory_bytes.png'
    fig.tight_layout()
    fig.savefig(str(png_file))
    print(f"Графік пам'яті збережено: {png_file.relative_to(SCRIPT_DIR.parent)}")
    plt.close(fig)
    
    return df_summary

# --- Точка входу ---

def parse_args() -> argparse.Namespace:
    """
    Парсинг аргументів командного рядка.
    """
    parser = argparse.ArgumentParser(description='Бенчмарк AES (CBC/GCM) проти RSA-Hybrid (CBC).')
    
    parser.add_argument(
        '--sizes', 
        type=str, 
        default=",".join(map(str, DEFAULT_SIZES)),
        help=f'Розміри даних в байтах, через кому (за замовчуванням: "1024,10240,102400,1048576")'
    )
    parser.add_argument(
        '--iterations', 
        type=int, 
        default=DEFAULT_ITERATIONS,
        help=f'Кількість ітерацій для кожного розміру (за замовчуванням: {DEFAULT_ITERATIONS})'
    )
    parser.add_argument(
        '--no-plots', 
        action='store_true', 
        help='Не зберігати графіки, лише CSV.'
    )
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()

    # Парсинг розмірів з рядка
    try:
        test_sizes = [int(s.strip()) for s in args.sizes.split(',') if s.strip()]
        if not test_sizes:
            raise ValueError("Список розмірів не може бути порожнім.")
    except Exception as e:
        print(f"Помилка парсингу --sizes: {e}. Використовуються значення за замовчуванням.", file=sys.stderr)
        test_sizes = DEFAULT_SIZES

    # Запуск бенчмарку
    df_results = run_benchmarks(test_sizes=test_sizes, iterations=args.iterations)

    if not df_results.empty:
        # Вивід зведених даних у консоль
        print('\n--- Зведені результати (середній час в мілісекундах) ---')
        # Агрегуємо та форматуємо для виводу
        df_summary_for_print = df_results.groupby(['method', 'size_bytes', 'operation'])['time_sec'].mean().unstack() * 1000
        print(df_summary_for_print.to_string(float_format="%.4f ms"))

        if not args.no_plots:
            print("\nГенерація графіків...")
            # Викликаємо функцію, яка також збереже зведений CSV
            summarize_and_plot(df_results) 
        else:
            print("\nПропуск генерації графіків (за вимогою --no-plots).")
    else:
        print("\nНе вдалося зібрати результати. Генерація графіків пропущена.")

    print('\nГотово.')