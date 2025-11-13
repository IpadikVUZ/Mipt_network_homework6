# ДЗ 6: Поэтический traceroute

### Запуск скрипта

```bash
sudo python3 traceroute_hijacker.py <iface_to_user> <iface_to_inet>
```
*   `<iface_to_user>`: интерфейс, смотрящий на клиентскую машину (например, `eth0`).
*   `<iface_to_inet>`: интерфейс, смотрящий в интернет (например, `eth1`).

### Тестирование

    ```bash
    traceroute olen.penis
    ```
    В выводе команды вместо IP-адресов маршрутизаторов появятся строки из песни.
