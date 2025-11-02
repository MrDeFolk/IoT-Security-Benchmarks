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
from typing import Any, Optional, Dict
import ssl
import threading

# --- Імпорти MQTT ---
try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Помилка: Бібліотеку 'paho-mqtt' не встановлено. Виконайте: pip install paho-mqtt", file=sys.stderr)
    sys.exit(1)

# --- Налаштування шляхів ---
SCRIPT_DIR = Path(__file__).parent.resolve()
# ОНОВЛЕНО: Вихідна директорія
OUTPUT_DIR = SCRIPT_DIR / "benchmarks" / "protocol_tests"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
# ОНОВЛЕНО: Шлях до сертифікатів у кореневій папці
CERT_DIR = SCRIPT_DIR / "certs"
CA_CERT_PATH = CERT_DIR / "ca.crt"
CLIENT_CERT_PATH = CERT_DIR / "client.crt"
CLIENT_KEY_PATH = CERT_DIR / "client.key"

# --- Глобальні налаштування бенчмарку ---
DEFAULT_ITERATIONS = 50
MQTT_HOST = "localhost"
MQTT_PLAIN_PORT = 1883
MQTT_TLS_PORT = 8883
PAYLOAD_SIZE = 128 # Розмір тестового повідомлення (байти)
RTT_TOPIC_SUB = "smarthome/benchmark/response"
RTT_TOPIC_PUB = "smarthome/benchmark/request"

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

# --- Логіка MQTT тестування ---

class MqttBenchmarkClient:
    """
    Інкапсулює логіку MQTT клієнта для вимірювання часу RTT.
    Використовує події (Events) для синхронізації між потоком paho-mqtt та головним потоком.
    ОНОВЛЕНО: Використовує paho-mqtt v2 API.
    """
    def __init__(self):
        self.client_id = f"benchmark-client-{secrets.token_hex(4)}"
        # ОНОВЛЕНО: Використання API v2
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=self.client_id)
        
        self.message_received_event = threading.Event()
        self.connected_event = threading.Event()
        self.subscribe_event = threading.Event()
        
        self.client.on_message = self.on_message
        self.client.on_connect = self.on_connect
        self.client.on_subscribe = self.on_subscribe
        self.last_error: Optional[str] = None

    @property
    def is_connected(self) -> bool:
        """
        Перевіряє, чи клієнт підключений та не має помилок.
        """
        # connected_event гарантує, що on_connect був викликаний
        return self.connected_event.is_set() and self.last_error is None

    # ОНОВЛЕНО: Сигнатура on_connect для API v2
    def on_connect(self, client, userdata, flags, rc, properties=None):
        """Викликається при (роз)підключенні."""
        if rc == mqtt.MQTT_ERR_SUCCESS:
            self.connected_event.set()
        else:
            self.last_error = f"Connection failed with code {rc}"
            self.connected_event.set()

    # ОНОВЛЕНО: Сигнатура on_subscribe для API v2
    def on_subscribe(self, client, userdata, mid, reason_code_list, properties=None):
        """Викликається при успішній підписці."""
        # reason_code_list - це список, перевіряємо, що в ньому немає помилок
        if all(rc.is_failure for rc in reason_code_list):
            self.last_error = f"Subscribe failed: {reason_code_list}"
        self.subscribe_event.set()

    # ОНОВЛЕНО: Сигнатура on_message для API v2 (залишилась такою ж)
    def on_message(self, client, userdata, msg):
        """Викликається при отриманні повідомлення."""
        self.message_received_event.set()

    def connect(self, host: str, port: int, tls_settings: Optional[Dict[str, Any]] = None) -> bool:
        """Встановлює з'єднання з брокером."""
        self.connected_event.clear()
        self.last_error = None

        if tls_settings:
            try:
                self.client.tls_set(
                    ca_certs=tls_settings["ca_certs"],
                    certfile=tls_settings["certfile"],
                    keyfile=tls_settings["keyfile"],
                    cert_reqs=ssl.CERT_REQUIRED,
                    tls_version=ssl.PROTOCOL_TLSv1_2
                )
                self.client.tls_insecure_set(False) 
            except Exception as e:
                self.last_error = f"TLS setup error: {e}"
                return False
        
        try:
            self.client.connect(host, port, 60)
            self.client.loop_start()
            
            if not self.connected_event.wait(timeout=5.0):
                self.last_error = "Connection timeout"
                self.client.loop_stop()
                return False
                
            if self.last_error:
                # Помилка буде оброблена у виклику (run_mqtt_benchmarks)
                self.client.loop_stop()
                return False
                
            return True
        except Exception as e:
            self.last_error = f"Connect exception: {e}"
            print(f"Помилка підключення до {host}:{port}: {e}", file=sys.stderr)
            self.client.loop_stop()
            return False

    def disconnect(self):
        """Від'єднується від брокера."""
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass

    def measure_rtt(self, payload: bytes) -> Optional[float]:
        """
        Вимірює час Round-Trip-Time (RTT).
        """
        try:
            self.message_received_event.clear()
            self.subscribe_event.clear()
            
            self.client.subscribe(RTT_TOPIC_SUB, qos=1)
            if not self.subscribe_event.wait(timeout=2.0):
                print("Тайм-аут підписки (SUBACK не отримано).", file=sys.stderr)
                return None
            if self.last_error and "Subscribe failed" in self.last_error:
                print(self.last_error, file=sys.stderr)
                return None

            t_start = time.perf_counter()
            self.client.publish(RTT_TOPIC_PUB, payload, qos=1)
            
            if not self.message_received_event.wait(timeout=5.0):
                print("Тайм-аут RTT (повідомлення не отримано).", file=sys.stderr)
                self.client.unsubscribe(RTT_TOPIC_SUB)
                return None
            
            t_end = time.perf_counter()
            self.client.unsubscribe(RTT_TOPIC_SUB)
            return (t_end - t_start)
        except Exception as e:
            print(f"Помилка RTT: {e}", file=sys.stderr)
            return None

def run_echo_client(port: int, tls_settings: Optional[Dict[str, Any]], stop_event: threading.Event):
    """
    Фоновий клієнт (Echo), що пересилає повідомлення.
    ОНОВЛЕНО: Використовує paho-mqtt v2 API.
    """
    client_id = f"benchmark-echo-server-{secrets.token_hex(4)}"
    echo_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    
    if tls_settings:
        try:
            echo_client.tls_set(**tls_settings)
        except Exception as e:
            print(f"[Echo-Клієнт] Помилка TLS: {e}", file=sys.stderr)
            stop_event.set()
            return

    def on_echo_connect(client, userdata, flags, rc, properties=None):
        if rc == mqtt.MQTT_ERR_SUCCESS:
            print(f"[Echo-Клієнт] Підключено (Порт {port}), слухаю {RTT_TOPIC_PUB}")
            client.subscribe(RTT_TOPIC_PUB, qos=1)
        else:
            print(f"[Echo-Клієнт] Помилка підключення: {rc} (Порт {port})", file=sys.stderr)
            stop_event.set()

    def on_echo_message(client, userdata, msg):
        client.publish(RTT_TOPIC_SUB, msg.payload, qos=1)

    echo_client.on_connect = on_echo_connect
    echo_client.on_message = on_echo_message

    try:
        echo_client.connect(MQTT_HOST, port, 60)
        while not stop_event.is_set():
            echo_client.loop(timeout=0.5)
    except Exception as e:
        print(f"[Echo-Клієнт] (Порт {port}) Помилка: {e}", file=sys.stderr)
    finally:
        print(f"[Echo-Клієнт] Зупинка (Порт {port}).")
        try:
            echo_client.disconnect()
        except Exception:
            pass

def run_mqtt_benchmarks(iterations: int) -> pd.DataFrame:
    """
    Запускає тести підключення та RTT для Plain MQTT та MQTT+TLS.
    """
    results: list[dict[str, Any]] = []
    
    if not (CERT_DIR.exists() and CA_CERT_PATH.exists() and CLIENT_CERT_PATH.exists() and CLIENT_KEY_PATH.exists()):
        print("="*60)
        print("ПОМИЛКА: Файли сертифікатів (ca.crt, client.crt, client.key) не знайдено.")
        print(f"Очікуваний шлях: {CERT_DIR.relative_to(SCRIPT_DIR)}")
        print("Тестування TLS неможливе. Перевірте шляхи або запустіть генерацію сертифікатів.")
        print("="*60)
        return pd.DataFrame()
    else:
        print(f"Сертифікати знайдено в: {CERT_DIR.relative_to(SCRIPT_DIR)}. TLS-тести увімкнено.")
        tls_settings = {
            "ca_certs": str(CA_CERT_PATH),
            "certfile": str(CLIENT_CERT_PATH),
            "keyfile": str(CLIENT_KEY_PATH),
        }

    stop_event_plain = threading.Event()
    echo_thread_plain = threading.Thread(
        target=run_echo_client, 
        args=(MQTT_PLAIN_PORT, None, stop_event_plain), 
        daemon=True
    )
    
    stop_event_tls = threading.Event()
    echo_thread_tls = threading.Thread(
        target=run_echo_client, 
        args=(MQTT_TLS_PORT, tls_settings, stop_event_tls), 
        daemon=True
    )
    
    print("Запуск фонових Echo-клієнтів (для Plain та TLS)...")
    echo_thread_plain.start()
    echo_thread_tls.start()
    time.sleep(3) # Даємо час клієнтам підключитися
    
    print(f"\nЗапуск тестів (Ітерацій: {iterations})")
    payload = secrets.token_bytes(PAYLOAD_SIZE)
    
    for i in tqdm(range(iterations), desc="Тести MQTT (Plain vs TLS)", leave=False):
        
        # --- Тест 1: Plain MQTT (1883) ---
        client_plain = MqttBenchmarkClient()
        _, time_conn_plain, mem_conn_plain = measure_time_and_memory(
            client_plain.connect, MQTT_HOST, MQTT_PLAIN_PORT
        )
        
        rtt_time_plain, mem_rtt_plain, rtt_success_plain = None, None, False
        # ОНОВЛЕНО: Використання властивості is_connected
        if client_plain.is_connected:
            rtt_result, mem_rtt_plain_op, _ = measure_time_and_memory(
                client_plain.measure_rtt, payload
            )
            rtt_time_plain = rtt_result
            rtt_success_plain = rtt_time_plain is not None
            mem_rtt_plain = mem_rtt_plain_op # Зберігаємо зміну пам'яті під час RTT
        client_plain.disconnect()

        results.append({
            'method': 'MQTT (Plain)',
            'time_connect_sec': time_conn_plain if client_plain.is_connected else None,
            'mem_delta_connect_bytes': mem_conn_plain,
            'rtt_sec': rtt_time_plain,
            'mem_delta_rtt_bytes': mem_rtt_plain,
            'success_rate': 1.0 if rtt_success_plain else 0.0
        })

        # --- Тест 2: MQTT over TLS (8883) ---
        client_tls = MqttBenchmarkClient()
        _, time_conn_tls, mem_conn_tls = measure_time_and_memory(
            client_tls.connect, MQTT_HOST, MQTT_TLS_PORT, tls_settings
        )
        
        rtt_time_tls, mem_rtt_tls, rtt_success_tls = None, None, False
        if client_tls.is_connected:
            rtt_result_tls, mem_rtt_tls_op, _ = measure_time_and_memory(
                client_tls.measure_rtt, payload
            )
            rtt_time_tls = rtt_result_tls
            rtt_success_tls = rtt_time_tls is not None
            mem_rtt_tls = mem_rtt_tls_op
        client_tls.disconnect()

        results.append({
            'method': 'MQTT over TLS',
            'time_connect_sec': time_conn_tls if client_tls.is_connected else None,
            'mem_delta_connect_bytes': mem_conn_tls,
            'rtt_sec': rtt_time_tls,
            'mem_delta_rtt_bytes': mem_rtt_tls,
            'success_rate': 1.0 if rtt_success_tls else 0.0
        })
        
    print("\nЗупинка Echo-клієнтів...")
    stop_event_plain.set()
    stop_event_tls.set()
    echo_thread_plain.join(timeout=2.0)
    echo_thread_tls.join(timeout=2.0)
        
    df = pd.DataFrame(results)
    out_csv = OUTPUT_DIR / "mqtt_overhead_benchmark_results.csv"
    df.to_csv(out_csv, index=False)
    print(f"\nРезультати збережено: {out_csv.relative_to(SCRIPT_DIR.parent)}")
    return df

# --- Візуалізація ---

def summarize_and_plot(df: pd.DataFrame) -> pd.DataFrame:
    """
    Агрегує дані та будує графіки.
    """
    if df.empty:
        print("DataFrame порожній, пропуск візуалізації.")
        return pd.DataFrame()

    df_summary = df.groupby('method').agg(
        time_connect_avg_sec=pd.NamedAgg(column='time_connect_sec', aggfunc='mean'),
        mem_delta_connect_bytes=pd.NamedAgg(column='mem_delta_connect_bytes', aggfunc='mean'),
        rtt_avg_sec=pd.NamedAgg(column='rtt_sec', aggfunc='mean'),
        mem_delta_rtt_bytes=pd.NamedAgg(column='mem_delta_rtt_bytes', aggfunc='mean'),
        success_rate=pd.NamedAgg(column='success_rate', aggfunc='mean')
    ).reset_index()

    csv_summary = OUTPUT_DIR / "mqtt_overhead_benchmark_summary.csv"
    df_summary.to_csv(csv_summary, index=False)
    print(f"Зведена таблиця збережена: {csv_summary.relative_to(SCRIPT_DIR.parent)}")

    # --- Графік Часу Підключення (мс) ---
    fig, ax = plt.subplots(figsize=(8, 5))
    df_summary['time_connect_avg_ms'] = df_summary['time_connect_avg_sec'] * 1000.0
    ax.bar(df_summary['method'], df_summary['time_connect_avg_ms'], color=['blue', 'green'])
    ax.set_ylabel('Середній час підключення (мілісекунди)')
    ax.set_title('Накладні витрати: Час підключення MQTT')
    ax.grid(axis='y', linestyle='--', linewidth=0.4)
    
    png_file = OUTPUT_DIR / 'mqtt_overhead_connect_time_ms.png'
    fig.tight_layout()
    fig.savefig(str(png_file))
    print(f"Графік часу підключення збережено: {png_file.relative_to(SCRIPT_DIR.parent)}")
    plt.close(fig)

    # --- Графік Часу RTT (мс) ---
    fig2, ax2 = plt.subplots(figsize=(8, 5))
    df_summary['rtt_avg_ms'] = df_summary['rtt_avg_sec'] * 1000.0
    ax2.bar(df_summary['method'], df_summary['rtt_avg_ms'], color=['blue', 'green'])
    ax2.set_ylabel('Середній час RTT (мілісекунди)')
    ax2.set_title('Накладні витрати: Час RTT (Publish-Subscribe)')
    ax2.grid(axis='y', linestyle='--', linewidth=0.4)
    
    png_file2 = OUTPUT_DIR / 'mqtt_overhead_rtt_time_ms.png'
    fig2.tight_layout()
    fig2.savefig(str(png_file2))
    print(f"Графік RTT збережено: {png_file2.relative_to(SCRIPT_DIR.parent)}")
    plt.close(fig2)

    return df_summary

# --- Точка входу ---

def parse_args() -> argparse.Namespace:
    """
    Парсинг аргументів командного рядка.
    """
    parser = argparse.ArgumentParser(description='Бенчмарк накладних витрат MQTT (Plain vs TLS).')
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
    
    print("="*60)
    print("  ВАЖЛИВО: Для цього тесту очікується, що MQTT брокер (Mosquitto)")
    print("  запущено на:")
    print(f"    - {MQTT_HOST}:{MQTT_PLAIN_PORT} (без шифрування)")
    print(f"    - {MQTT_HOST}:{MQTT_TLS_PORT} (з TLS та автентифікацією за сертифікатами)")
    print("="*60)
    
    # Перевірка наявності сертифікатів
    if not (CERT_DIR.exists() and CA_CERT_PATH.exists() and CLIENT_CERT_PATH.exists() and CLIENT_KEY_PATH.exists()):
         print(f"\nПОМИЛКА: Директорія сертифікатів '{CERT_DIR.relative_to(SCRIPT_DIR)}' або")
         print("  необхідні файли (ca.crt, client.crt, client.key) в ній не знайдено.")
         print("  Будь ласка, скопіюйте сертифікати у цю директорію перед запуском.")
         sys.exit(1)
    else:
        print(f"Сертифікати знайдено в: {CERT_DIR.relative_to(SCRIPT_DIR)}. Продовження через 3 сек...")
        time.sleep(3) # Даємо час прочитати
    
    df_results = run_mqtt_benchmarks(iterations=args.iterations)
    
    if not df_results.empty:
        print('\n--- Зведені результати (середні) ---')
        # Агрегуємо дані для виводу
        df_summary_print = df_results.groupby('method').agg(
            time_connect_avg_sec=('time_connect_sec', 'mean'),
            rtt_avg_sec=('rtt_sec', 'mean'),
            success_rate=('success_rate', 'mean')
        ).reset_index()
        
        df_summary_print['time_connect_avg_ms'] = df_summary_print['time_connect_avg_sec'] * 1000.0
        df_summary_print['rtt_avg_ms'] = df_summary_print['rtt_avg_sec'] * 1000.0
        
        # Виводимо відформатовану таблицю
        print(df_summary_print[['method', 'time_connect_avg_ms', 'rtt_avg_ms', 'success_rate']].to_string(float_format="%.4f"))
        
        if not args.no_plots:
            print("\nГенерація графіків...")
            # Функція summarize_and_plot сама збереже зведений CSV
            summarize_and_plot(df_results)
        else:
            print("\nПропуск генерації графіків (за вимогою --no-plots).")
    else:
        print("\nНе вдалося зібрати результати. Генерація графіків пропущена.")

    print('\nГотово.')