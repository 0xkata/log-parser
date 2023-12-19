"""
Tasks
1. Read file
2. Extract data
3. Analysis (?)
4. Create report 

"""

import argparse
import re
import pandas as pd
from tqdm import tqdm


def log_to_df(filename, output, error):
    combined_regex = '^(?P<client>\S+) \S+ (?P<userid>\S+) \[(?P<datetime>[^\]]+)\] "(?P<method>[A-Z]+) (?P<request>.+?) HTTP/[0-9.]+" (?P<status>[0-9]{3}) (?P<size>[0-9]+|-) "(?P<referrer>[^"]*)" "(?P<useragent>[^"]*)"'

    columns = [
        "client",
        "userid",
        "datetime",
        "method",
        "request",
        "status",
        "size",
        "referer",
        "user_agent",
    ]

    with open(filename, "r") as file:
        line_num = 0
        parsed_lines = []
        for line in tqdm(file):
            try:
                cur_line = re.findall(combined_regex, line)[0]
                parsed_lines.append(cur_line)
            except Exception as e:
                with open(error, "at") as err:
                    print((line, str(e)), file=err)
                continue

            line_num += 1

            if line_num % 250_000 == 0:
                df = pd.DataFrame(parsed_lines, columns=columns)
                df.to_parquet(f"{output}/file{line_num//250_000}.parquet")
                parsed_lines.clear()

        else:  # Handle the last batch
            df = pd.DataFrame(parsed_lines, columns=columns)
            df.to_parquet(f"{output}/file{line_num//250_000}.parquet")
            parsed_lines.clear()


def format_df(df):
    df["datetime"] = pd.to_datetime(df["datetime"], format="%d/%b/%Y:%H:%M:%S %z")
    df["status"] = df["status"].astype(int)
    df["size"] = pd.to_numeric(df["size"], errors="coerce")
    df.dropna(inplace=True)


def detect_sql(df):
    sqli_patterns = [
        "';--",
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR 0=0 --",
        "' OR x=x --",
        "admin' --",
        "') OR ('",
        "'; EXEC",
        "' UNION SELECT",
        "'; DROP",
        "' AND SLEEP(",
    ]

    sqli_patterns = [pattern.lower() for pattern in sqli_patterns]

    df["sqli_flag"] = (
        df["request"]
        .str.lower()
        .apply(lambda x: any(pattern in x for pattern in sqli_patterns))
    )


def detect_xss(df):
    xss_patterns = ["<script", "javascript:", "onerror=", "onload="]
    df["xss_flag"] = df["request"].apply(
        lambda x: any(pattern in x for pattern in xss_patterns)
    )


def main():
    parser = argparse.ArgumentParser(
        description="Allows user to parse a log file and create a report",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("FILE")
    args = parser.parse_args()
    filename = str(args.FILE)
    log_to_df(filename, "parquet/", "error.txt")
    df = pd.read_parquet("parquet/")
    format_df(df)
    detect_sql(df)
    detect_xss(df)
    sus_sql = df[df["sqli_flag"]]
    sus_xss = df[df["xss_flag"]]

    df.to_csv("output.csv", index=False)
    sus_sql.to_csv("sqli.csv", index=False)
    sus_xss.to_csv("xss.csv", index=False)


if __name__ == "__main__":
    main()
