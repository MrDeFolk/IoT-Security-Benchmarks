import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
import sys # Для sys.exit

# --- Налаштування шляхів ---
# Визначаємо кореневу директорію проєкту (де лежить `benchmarks_plot.py`)
BASE_DIR = Path(__file__).parent.resolve()
# Директорія з результатами бенчмарків
BENCHMARKS_DIR = BASE_DIR / "benchmarks"
# Очікувані файли з даними (шляхи до підпапок)
AES_CSV = BENCHMARKS_DIR / "encryption_tests" / "aes_vs_rsa_summary.csv"
AUTH_CSV = BENCHMARKS_DIR / "authentication_tests" / "totp_vs_argon2_summary.csv"
PROTO_CSV = BENCHMARKS_DIR / "protocol_tests" / "mqtt_overhead_benchmark_summary.csv"
# Файл для збереження фінального графіку
RADAR_PNG = BENCHMARKS_DIR / "00_overall_performance_radar.png"

def save_fig(fig, fname: Path, dpi: int = 300):
    """
    Допоміжна функція для збереження графіку Matplotlib у файл.
    """
    fig.tight_layout()
    try:
        fig.savefig(str(fname), dpi=dpi)
        print(f"Графік збережено: {fname.relative_to(BASE_DIR)}")
    except Exception as e:
        print(f"Не вдалося зберегти графік {fname.relative_to(BASE_DIR)}: {e}")
    plt.close(fig)

def safe_read_csv(path: Path) -> pd.DataFrame:
    """
    Безпечно читає CSV-файл. Повертає порожній DataFrame, якщо файл не знайдено.
    """
    if not path.exists():
        print(f"Попередження: Файл даних не знайдено, буде пропущено: {path.relative_to(BASE_DIR)}")
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except pd.errors.EmptyDataError:
        print(f"Попередження: Файл даних порожній: {path.relative_to(BASE_DIR)}")
        return pd.DataFrame()
    except Exception as e:
        print(f"Помилка читання {path.relative_to(BASE_DIR)}: {e}")
        return pd.DataFrame()

def normalize_inverse(series: pd.Series) -> pd.Series:
    """
    Нормалізує дані за принципом "чим менше, тим краще". (0-100)
    """
    s = series.astype(float)
    s_valid = s.dropna()
    if s_valid.empty or len(s_valid) < 2 or (s_valid.max() == s_valid.min()):
        return pd.Series([50.0] * len(s), index=s.index) # Повертаємо 50, якщо всі значення однакові
    
    # (max - current) / (max - min)
    out = (s_valid.max() - s) / (s_valid.max() - s_valid.min()) * 100.0
    mean_val = out.mean()
    out_full = out.reindex(s.index).fillna(mean_val)
    return out_full.clip(0, 100)

def normalize_direct(series: pd.Series) -> pd.Series:
    """
    Нормалізує дані за принципом "чим більше, тим краще". (0-100)
    """
    s = series.astype(float)
    s_valid = s.dropna()
    if s_valid.empty or len(s_valid) < 2 or (s_valid.max() == s_valid.min()):
        return pd.Series([100.0] * len(s), index=s.index) # Успішність за замовчуванням 100%
        
    # (current - min) / (max - min)
    out = (s - s_valid.min()) / (s_valid.max() - s_valid.min()) * 100.0
    mean_val = out.mean()
    out_full = out.reindex(s.index).fillna(mean_val)
    return out_full.clip(0, 100)

def plot_overall_radar(df_aes: pd.DataFrame, df_auth: pd.DataFrame, df_proto: pd.DataFrame):
    """
    Побудова зведеної радарної діаграми для візуалізації результатів.
    """
    rows = {}

    # --- Збір даних про шифрування (AES vs Hybrid) ---
    if not df_aes.empty:
        # Беремо середні значення 'encrypt' для всіх розмірів файлів
        # ВИПРАВЛЕНО: Агрегуємо існуючі колонки mean_time_sec та mean_mem_bytes
        df_aes_agg = df_aes[df_aes['operation'] == 'encrypt'].groupby('method').agg(
            mean_time_sec=('mean_time_sec', 'mean'),
            mean_mem_bytes=('mean_mem_bytes', 'mean')
        ).reset_index()
        for _, row in df_aes_agg.iterrows():
            rows[row['method']] = {'time': row['mean_time_sec'], 'mem': row['mean_mem_bytes'], 'success': 1.0}

    # --- Збір даних про автентифікацію (Argon2 vs TOTP) ---
    if not df_auth.empty:
        # Беремо лише операції 'verify'
        df_auth_verify = df_auth[df_auth['operation'] == 'verify'].set_index('method')
        if 'Argon2' in df_auth_verify.index:
            rows['Argon2 (Verify)'] = {'time': df_auth_verify.loc['Argon2', 'mean_time_sec'], 'mem': df_auth_verify.loc['Argon2', 'mean_mem_bytes'], 'success': 1.0}
        if 'TOTP' in df_auth_verify.index:
            rows['TOTP (Verify)'] = {'time': df_auth_verify.loc['TOTP', 'mean_time_sec'], 'mem': df_auth_verify.loc['TOTP', 'mean_mem_bytes'], 'success': 1.0}

    # --- Збір даних про протоколи (MQTT vs MQTT+TLS) ---
    if not df_proto.empty:
        # Беремо середній RTT та успішність
        # Цей блок вже був правильним, оскільки він читав коректні імена колонок
        df_proto_agg = df_proto.groupby('method').agg(
            mean_time_sec=('rtt_avg_sec', 'mean'),
            mean_mem_bytes=('mem_delta_rtt_bytes', 'mean'),
            success=('success_rate', 'mean')
        ).reset_index()
        for _, row in df_proto_agg.iterrows():
            rows[row['method']] = {'time': row['mean_time_sec'], 'mem': row['mean_mem_bytes'], 'success': row['success']}

    if not rows:
        print("Немає експериментальних даних для радару — пропускаємо побудову.")
        return

    df_all = pd.DataFrame.from_dict(rows, orient='index')
    df_all = df_all.ffill().fillna(0) # Заповнення пропусків

    # --- Нормалізація ---
    scores = pd.DataFrame(index=df_all.index)
    scores['Швидкодія (Час)'] = normalize_inverse(df_all['time'])
    scores['Ефективність (Пам\'ять)'] = normalize_inverse(df_all['mem'])
    scores['Надійність'] = normalize_direct(df_all['success'])
    
    # Видаляємо методи, які не є ключовими для фінального порівняння
    # 'AES-GCM-256' - для порівняння, 'AES-CBC-256' - аналог C#
    plot_df = scores.drop(index=['AES-GCM-256'], errors='ignore')
    
    # Сортуємо для кращої візуалізації
    plot_df = plot_df.sort_values(by='Швидкодія (Час)', ascending=False)
    
    labels = plot_df.columns.tolist()
    num_vars = len(labels)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    angles += angles[:1] # Замикаємо коло

    fig = plt.figure(figsize=(10, 10))
    ax = fig.add_subplot(111, polar=True)

    for idx, row in plot_df.iterrows():
        values = row.tolist()
        values += values[:1] # Замикаємо коло
        ax.plot(angles, values, label=str(idx), linewidth=2, marker='o')
        ax.fill(angles, values, alpha=0.15)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, fontsize=12)
    ax.set_ylim(0, 100)
    ax.set_title("Зведена оцінка механізмів безпеки (0=Гірше, 100=Краще)", fontsize=16, pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(1.4, 1.1))

    save_fig(fig, RADAR_PNG)

def main():
    print("Генерація зведеного графіку...")
    BENCHMARKS_DIR.mkdir(parents=True, exist_ok=True) # Створюємо папку, якщо її немає
    
    # Читаємо всі необхідні CSV
    df_aes = safe_read_csv(AES_CSV)
    df_auth = safe_read_csv(AUTH_CSV)
    df_proto = safe_read_csv(PROTO_CSV)
    
    if df_aes.empty and df_auth.empty and df_proto.empty:
        print("ПОМИЛКА: Не знайдено жодного CSV-файлу з результатами.")
        print(f"Перевірте наявність файлів у директорії: {BENCHMARKS_DIR.relative_to(BASE_DIR)}")
        sys.exit(1)

    plot_overall_radar(df_aes, df_auth, df_proto)
    print("Генерація графіку завершена.")

if __name__ == "__main__":
    main()