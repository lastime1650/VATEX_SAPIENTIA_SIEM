import datetime

import datetime

def now_to_nano_int() -> int:
    """
    현재 로컬(now) 기준 나노초 단위의 부호 없는 8바이트 정수(int) 반환
    """
    # 현재 로컬 시각 기준 datetime
    now = datetime.datetime.now().astimezone()
    epoch = datetime.datetime(1970, 1, 1, tzinfo=now.tzinfo)
    
    # Epoch부터의 시간차 계산
    delta = now - epoch
    nanoseconds = int(delta.total_seconds() * 1_000_000_000) + now.microsecond * 1000
    return nanoseconds

import time

def now_to_nano_int_2() -> int:
    """
    현재 시각을 UTC Epoch 기준 나노초 단위의 정수(int)로 반환합니다.
    """
    return time.time_ns()

'''def nano_to_iso_string(nanoseconds: int) -> str:
    """
    19자리 나노초 정수를 ISO 8601 로컬 시각 문자열로 변환합니다.
    예: 1730105630112233500 -> "2024-10-28T18:33:50.112233500+09:00"
    """
    seconds = nanoseconds // 1_000_000_000
    nanos_part = nanoseconds % 1_000_000_000

    # 로컬 타임존 기준으로 변환
    dt_object = datetime.datetime.fromtimestamp(seconds).astimezone()

    base_format = dt_object.strftime('%Y-%m-%dT%H:%M:%S')

    return f"{base_format}.{nanos_part:09d}Z"'''


def nano_to_iso_string(nanoseconds: int) -> str:
    seconds = nanoseconds // 1_000_000_000
    nanos_part = nanoseconds % 1_000_000_000
    
    # [수정] tz=timezone.utc를 넣어주어야 UTC 기준으로 datetime 객체가 생성됩니다.
    dt_object = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    
    # 이제 dt_object는 14시(UTC)를 가리킵니다.
    base_format = dt_object.strftime('%Y-%m-%dT%H:%M:%S')
    
    return f"{base_format}.{nanos_part:09d}Z"

# --- 함수 테스트 ---
ts_nano = 1763563075677665700
iso_string = nano_to_iso_string(ts_nano)
print(f"{ts_nano} -> {iso_string}")


print(
    
    nano_to_iso_string( ts_nano )
)