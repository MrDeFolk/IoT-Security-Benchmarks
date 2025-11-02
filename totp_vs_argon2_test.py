import os
import sys
import time
import gc
import secrets
import argparse
from pathlib import Path
from typing import Any, Optional
import psutil
from tqdm import tqdm
import pandas as pd
import matplotlib.pyplot as plt

# --- Імпорти бібліотек автентифікації ---
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
except ImportError:
    # Виводимо повідомлення про помилку, якщо бібліотека не встановлена
    print("Помилка: Бібліотеку 'argon2-cffi' не встановлено. Виконайте: pip install argon2-cffi", file=sys.stderr)
    sys.exit(1)

try:
    import pyotp
except ImportError:
    print("Помилка: Бібліотеку 'pyotp' не встановлено. Виконайте: pip install pyotp", file=sys.stderr)
    sys.exit(1)

# --- Налаштування шляхів ---
SCRIPT_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = SCRIPT_DIR / "benchmarks" / "authentication_tests"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --- Глобальні налаштування бенчмарку ---
DEFAULT_ITERATIONS = 50

# Налаштування Argon2 (помірні, для швидких тестів)
# Ці параметри імітують налаштування, рекомендовані OWASP (але зі зниженими ітераціями)
ARGON2_TIME_COST = 2      # Кількість ітерацій
ARGON2_MEMORY_COST_KB = 65536  # 64 MB
ARGON2_PARALLELISM = 1    # Кількість потоків

# Процес для моніторингу пам'яті
_process = psutil.Process(os.getpid())

# --- Допоміжні функції ---

def measure_time_and_memory(func: Any, *args, **kwargs) -> tuple[Any, float, int]:
    """
    Вимірює час виконання (в секундах) та зміну RSS пам'яті (в байтах).
    Повертає: (результат_функції, час_виконання, зміна_памяті)
    """
    gc.collect()
    mem_before = _process.memory_info().rss
    t_start = time.perf_counter()
    result = func(*args, **kwargs)
    t_end = time.perf_counter()
    gc.collect()
    mem_after = _process.memory_info().rss
    return result, (t_end - t_start), (mem_after - mem_before)

def gen_random_password(length: int = 16) -> str:
    """Генерує випадковий пароль заданої довжини."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# --- Функції для тестування Argon2 ---

def argon2_setup() -> PasswordHasher:
    """Створює екземпляр PasswordHasher з глобальними налаштуваннями."""
    return PasswordHasher(
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KB,
        parallelism=ARGON2_PARALLELISM
    )

def argon2_hash(ph: PasswordHasher, password: str) -> str:
    """Виконує хешування пароля."""
    return ph.hash(password)

def argon2_verify(ph: PasswordHasher, hash_str: str, password: str) -> bool:
    """Виконує верифікацію пароля. Повертає True/False."""
    try:
        # ph.verify() повертає True, якщо хеш вірний,
        # або кидає виняток VerifyMismatchError, якщо ні.
        return ph.verify(hash_str, password)
    except VerifyMismatchError:
        return False # Пароль невірний
    except Exception as e:
        print(f"Помилка верифікації Argon2: {e}", file=sys.stderr)
        return False # Інша помилка

# --- Функції для тестування TOTP ---

def totp_setup() -> pyotp.TOTP:
    """Створює TOTP-об'єкт з випадковим 32-байтним (256-біт) секретом."""
    secret = pyotp.random_base32(length=32) # Використовуємо довший ключ
    return pyotp.TOTP(secret, interval=30) # Стандартний 30-сек інтервал

def totp_generate_code(totp: pyotp.TOTP) -> str:
    """Генерує поточний TOTP код."""
    return totp.now()

def totp_verify_code(totp: pyotp.TOTP, code: str) -> bool:
    """Верифікує TOTP код (з стандартним вікном +/- 1)."""
    # for_time використовується для імітації перевірки в той самий момент часу
    return totp.verify(code, for_time=time.time(), window=1)

# --- Логіка бенчмарку ---

def run_auth_benchmarks(iterations: int) -> pd.DataFrame:
    """
    Запускає бенчмарки Argon2 та TOTP.
    Порівнює операції 'hash'/'verify' (Argon2) та 'generate'/'verify' (TOTP).
    Це порівняння двох РІЗНИХ за призначенням механізмів:
    - Argon2: Захист пароля при зберіганні (повільний, ресурсоємний).
    - TOTP: Генерація/перевірка токена (швидкий, легкий).
    """
    results: list[dict[str, Any]] = []
    
    print(f"Запуск тестів автентифікації (Ітерацій: {iterations})")
    print(f"Параметри Argon2: time_cost={ARGON2_TIME_COST}, memory_cost={ARGON2_MEMORY_COST_KB}KB, parallelism={ARGON2_PARALLELISM}")
    
    # Створюємо об'єкти один раз
    ph = argon2_setup()
    totp = totp_setup()

    for i in tqdm(range(iterations), desc="Тести автентифікації", leave=False):
        password = gen_random_password()
        
        # --- Тест 1: Argon2 (Hash) ---
        try:
            # ВИПРАВЛЕНО: Зберігаємо результат (hashed_pass) з першого виклику
            hashed_pass, time_hash, mem_hash = measure_time_and_memory(argon2_hash, ph, password)
            results.append({'method': 'Argon2', 'operation': 'hash', 'time_sec': time_hash, 'mem_delta_bytes': mem_hash, 'success': True})
            
            # --- Тест 2: Argon2 (Verify) ---
            # Перевіряємо з правильним паролем
            _, time_verify, mem_verify = measure_time_and_memory(argon2_verify, ph, hashed_pass, password)
            results.append({'method': 'Argon2', 'operation': 'verify', 'time_sec': time_verify, 'mem_delta_bytes': mem_verify, 'success': True})
        
        except Exception as e:
            print(f"Помилка тестування Argon2: {e}", file=sys.stderr)
            results.append({'method': 'Argon2', 'operation': 'hash', 'time_sec': None, 'mem_delta_bytes': None, 'success': False})
            results.append({'method': 'Argon2', 'operation': 'verify', 'time_sec': None, 'mem_delta_bytes': None, 'success': False})

        # --- Тест 3: TOTP (Generate) ---
        try:
            # ВИПРАВЛЕНО: Зберігаємо результат (code) з першого виклику
            code, time_gen, mem_gen = measure_time_and_memory(totp_generate_code, totp)
            results.append({'method': 'TOTP', 'operation': 'generate', 'time_sec': time_gen, 'mem_delta_bytes': mem_gen, 'success': True})

            # --- Тест 4: TOTP (Verify) ---
            # Перевіряємо з правильним, щойно згенерованим кодом
            _, time_vfy, mem_vfy = measure_time_and_memory(totp_verify_code, totp, code)
            results.append({'method': 'TOTP', 'operation': 'verify', 'time_sec': time_vfy, 'mem_delta_bytes': mem_vfy, 'success': True})
        
        except Exception as e:
            print(f"Помилка тестування TOTP: {e}", file=sys.stderr)
            results.append({'method': 'TOTP', 'operation': 'generate', 'time_sec': None, 'mem_delta_bytes': None, 'success': False})
            results.append({'method': 'TOTP', 'operation': 'verify', 'time_sec': None, 'mem_delta_bytes': None, 'success': False})

    df = pd.DataFrame(results)
    out_csv = OUTPUT_DIR / "totp_vs_argon2_results.csv"
    df.to_csv(out_csv, index=False)
    print(f"\nРезультати збережено: {out_csv.relative_to(SCRIPT_DIR.parent)}")
    return df

# --- Візуалізація ---

def summarize_and_plot(df: pd.DataFrame) -> pd.DataFrame:
    """
    Агрегує дані та будує графіки часу та пам'яті.
    """
    if df.empty:
        print("DataFrame порожній, пропуск візуалізації.")
        return pd.DataFrame()

    # Агрегуємо середні значення часу та пам'яті
    df_summary = df.groupby(['method', 'operation']).agg(
        mean_time_sec=pd.NamedAgg(column='time_sec', aggfunc='mean'),
        mean_mem_bytes=pd.NamedAgg(column='mem_delta_bytes', aggfunc='mean'),
        success_rate=pd.NamedAgg(column='success', aggfunc='mean'),
    ).reset_index()

    csv_summary = OUTPUT_DIR / "totp_vs_argon2_summary.csv"
    df_summary.to_csv(csv_summary, index=False)
    print(f"Зведена таблиця збережена: {csv_summary.relative_to(SCRIPT_DIR.parent)}")

    # --- Графік Часу (мс) ---
    fig, ax = plt.subplots(figsize=(10, 6))
    labels = df_summary['method'] + ' - ' + df_summary['operation']
    times_ms = df_summary['mean_time_sec'] * 1000.0 # у мілісекундах
    
    bars = ax.bar(labels, times_ms)
    ax.set_ylabel('Середній час (мілісекунди)')
    ax.set_title('Порівняння часу виконання: Argon2 vs TOTP')
    ax.set_xticklabels(labels, rotation=45, ha='right')
    ax.grid(axis='y', linestyle='--', linewidth=0.4)
    
    # ПОКРАЩЕННЯ: Використовуємо логарифмічну шкалу, оскільки різниця буде величезною
    ax.set_yscale('log')
    ax.set_ylabel('Середній час (мілісекунди, лог. шкала)')
    
    png_file = OUTPUT_DIR / 'totp_vs_argon2_time_ms.png'
    fig.tight_layout()
    fig.savefig(str(png_file))
    print(f"Графік часу збережено: {png_file.relative_to(SCRIPT_DIR.parent)}")
    plt.close(fig)

    # --- Графік Пам'яті (байти) ---
    fig2, ax2 = plt.subplots(figsize=(10, 6))
    mems = df_summary['mean_mem_bytes'].fillna(0)
    ax2.bar(labels, mems)
    ax2.set_ylabel('Середня зміна RSS пам\'яті (байти)')
    ax2.set_title('Порівняння використання пам\'яті: Argon2 vs TOTP')
    ax2.set_xticklabels(labels, rotation=45, ha='right')
    ax2.grid(axis='y', linestyle='--', linewidth=0.4)
    
    # ПОКРАЩЕННЯ: Використовуємо логарифмічну шкалу для пам'яті
    ax2.set_yscale('log')
    ax2.set_ylabel('Середня зміна RSS пам\'яті (байти, лог. шкала)')

    png_file2 = OUTPUT_DIR / 'totp_vs_argon2_mem_bytes.png'
    fig2.tight_layout()
    fig2.savefig(str(png_file2))
    print(f"Графік пам'яті збережено: {png_file2.relative_to(SCRIPT_DIR.parent)}")
    plt.close(fig2)

    return df_summary

# --- Точка входу ---

def parse_args() -> argparse.Namespace:
    """
    Парсинг аргументів командного рядка.
    """
    parser = argparse.ArgumentParser(description='Бенчмарк Argon2 проти TOTP.')
    parser.add_argument(
        '--iterations', 
        type=int, 
        default=DEFAULT_ITERATIONS, 
        help=f'Кількість ітерацій (за замовчуванням: {DEFAULT_ITERATIONS})'
    )
    parser.add_argument(
        '--no-plots', 
        action='store_true', 
        help='Не зберігати графіки, лише CSV.'
    )
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    
    df_results = run_auth_benchmarks(iterations=args.iterations)
    
    if not df_results.empty:
        print('\n--- Зведені результати (середні) ---')
        # Розраховуємо середні значення для виводу в консоль
        df_summary_print = df_results.groupby(['method', 'operation'])[['time_sec', 'mem_delta_bytes']].mean().reset_index()
        df_summary_print['time_ms'] = df_summary_print['time_sec'] * 1000.0
        print(df_summary_print[['method', 'operation', 'time_ms', 'mem_delta_bytes']].to_string(float_format="%.4f"))
        
        if not args.no_plots:
            print("\nГенерація графіків...")
            # Функція summarize_and_plot сама збереже зведений CSV
            summarize_and_plot(df_results)
        else:
            print("\nПропуск генерації графіків (за вимогою --no-plots).")
    else:
        print("\nНе вдалося зібрати результати. Генерація графіків пропущена.")

    print('\nГотово.')