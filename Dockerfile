FROM python:3.12-slim-bookworm

# For hosts without a usable BlueZ (e.g. Synology DSM): the container runs
# its own dbus + bluetoothd, and needs --net=host --privileged for raw HCI
# access. On a normal Linux box that already runs bluetoothd, skip Docker and
# run scale_reader.py directly instead -- two bluetoothds fighting over one
# adapter doesn't work. kmod is for the optional module loading in
# entrypoint.sh.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bluez dbus kmod \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY scale_reader.py decode_btsnoop.py ./
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
