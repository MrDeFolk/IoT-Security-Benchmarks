import subprocess
import sys
from pathlib import Path
from typing import Dict

# --- Налаштування шляхів ---
# Визначаємо кореневу директорію проєкту (де лежить `Run_benchmarks.py`)
ROOT_DIR = Path(__file__).parent.resolve()

# ОНОВЛЕНО: Словник тестів тепер вказує на файли у кореневій папці.
TEST_SCRIPTS: Dict[str, Path] = {
    "1. Автентифікація (Argon2 vs TOTP)": ROOT_DIR / "totp_vs_argon2_test.py",
    "2. Шифрування (AES vs RSA-Hybrid)": ROOT_DIR / "aes_vs_rsa_benchmark.py",
    "3. MQTT (Plain vs TLS Overhead)": ROOT_DIR / "mqtt_overhead_benchmark.py",
    "4. Генерація зведеного графіку": ROOT_DIR / "benchmarks_plot.py",
}

def show_menu() -> str:
    """
    Відображає інтерактивне меню для вибору тестів.
    Повертає вибір користувача.
    """
    print("\n" + "="*40)
    print("  Меню запуску бенчмарків (IoT Security)")
    print("="*40)
    print("Доступні тести:")
    for key, path in TEST_SCRIPTS.items():
        # Показуємо відносний шлях (буде просто ім'я файлу)
        print(f"  {key} ({path.relative_to(ROOT_DIR)})")
    
    print("\n  'Y' - Запустити всі тести (1, 2, 3) та згенерувати графік (4)")
    print("  'N' - Вийти")

    choice = input("\nВведіть номер тесту (1-4), 'Y' або 'N': ").strip().lower()
    return choice

def run_script(script_path: Path, common_args: list[str]):
    """
    Безпечно запускає Python-скрипт як окремий процес.
    Передає спільні аргументи (напр., --iterations).
    """
    if not script_path.exists():
        print(f"ПОМИЛКА: Файл не знайдено: {script_path.relative_to(ROOT_DIR)}")
        return

    print("-" * 50)
    print(f"Запуск: {script_path.name}")
    print(f"   (Аргументи: {' '.join(common_args) if common_args else 'немає'})")
    print("-" * 50)
    
    try:
        # Використовуємо той самий інтерпретатор Python, що й для запуску цього скрипта
        subprocess.run(
            [sys.executable, str(script_path)] + common_args, 
            check=True,
            # Встановлюємо робочу директорію на корінь проєкту
            cwd=ROOT_DIR
        )
    except subprocess.CalledProcessError as e:
        print(f"ПОМИЛКА під час виконання {script_path.name}: {e}")
    except KeyboardInterrupt:
        print(f"\nПерервано користувачем: {script_path.name}")
        sys.exit(1) # Виходимо з головного скрипта
    print("-" * 50)
    print(f"Завершено: {script_path.name}")
    print("-" * 50)


def main():
    """
    Головний цикл обробки вибору користувача.
    """
    # Збираємо всі аргументи, передані цьому скрипту, щоб передати їх дочірнім
    # Наприклад: python Run_benchmarks.py --iterations 100
    common_args = sys.argv[1:] 
    
    while True:
        choice = show_menu()
        
        if choice == 'n':
            print("Вихід.")
            break
        
        if choice == 'y':
            print("Запуск усіх тестів...")
            # Запускаємо тести
            run_script(TEST_SCRIPTS["1. Автентифікація (Argon2 vs TOTP)"], common_args)
            run_script(TEST_SCRIPTS["2. Шифрування (AES vs RSA-Hybrid)"], common_args)
            run_script(TEST_SCRIPTS["3. MQTT (Plain vs TLS Overhead)"], common_args)
            
            # Генеруємо графік (без додаткових аргументів)
            print("\nГенерація зведеного графіку...")
            run_script(TEST_SCRIPTS["4. Генерація зведеного графіку"], [])
            print("\nУсі завдання виконано.")
            break
            
        # Пошук за цифрою "1", "2" і т.д.
        found = False
        for key in TEST_SCRIPTS.keys():
            if key.startswith(choice):
                # Для 4-го скрипта (графік) не передаємо аргументи
                args_to_pass = common_args if not key.startswith("4") else []
                run_script(TEST_SCRIPTS[key], args_to_pass)
                found = True
                break
        
        if not found and choice not in ('y', 'n'):
            print("Невідомий вибір. Спробуйте ще раз.")

if __name__ == "__main__":
    main()