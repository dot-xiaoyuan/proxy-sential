// Frozen comparison copied from the user-maintained “网段核查” sheet on 2026-11-15.
// Overlapping /16, /24 and single-IP rows are counted as fact rows, never summed as devices.
export const deviceFactSnapshot = {
  "source": "https://docs.google.com/spreadsheets/d/1J9Nn2mSGNTVbt7CweW-PvDazkoYmlFe2cE21kbFsPXY/edit?gid=1715282976",
  "observedAt": "2026-11-15 09:35:11 +08:00",
  "flowWindow": "2026-11-15 09:06–09:36 +08:00",
  "rows": [
    {
      "id": "7",
      "range": "222.204.1.109-222.204.1.110",
      "kind": "未明确",
      "mirror": 0,
      "identified": 0,
      "status": "未见镜像IP"
    },
    {
      "id": "10",
      "range": "10.131.32.0/24",
      "kind": "未明确",
      "mirror": 0,
      "identified": 0,
      "status": "未见镜像IP"
    },
    {
      "id": "12",
      "range": "10.131.255.0/24",
      "kind": "未明确",
      "mirror": 0,
      "identified": 0,
      "status": "未见镜像IP"
    },
    {
      "id": "29",
      "range": "10.152.250.0/24",
      "kind": "下挂设备（类型未知）",
      "mirror": 0,
      "identified": 0,
      "status": "未见镜像IP"
    },
    {
      "id": "30",
      "range": "10.152.251.0/24",
      "kind": "路由器",
      "mirror": 0,
      "identified": 0,
      "status": "未见镜像IP"
    },
    {
      "id": "31",
      "range": "10.152.249.0/24",
      "kind": "测试设备",
      "mirror": 0,
      "identified": 0,
      "status": "未见镜像IP"
    },
    {
      "id": "35",
      "range": "10.161.2.0/24",
      "kind": "未明确",
      "mirror": 0,
      "identified": 0,
      "status": "未见镜像IP"
    },
    {
      "id": "1",
      "range": "10.126.255.0/24",
      "kind": "未明确",
      "mirror": 4,
      "identified": 2,
      "status": "已有类型识别"
    },
    {
      "id": "2",
      "range": "10.126.254.0/24",
      "kind": "摄像头",
      "mirror": 40,
      "identified": 18,
      "status": "已有类型识别"
    },
    {
      "id": "3",
      "range": "10.126.253.0/24",
      "kind": "门禁设备",
      "mirror": 7,
      "identified": 5,
      "status": "已有类型识别"
    },
    {
      "id": "4",
      "range": "10.126.252.0/24",
      "kind": "动环监控设备",
      "mirror": 10,
      "identified": 7,
      "status": "已有类型识别"
    },
    {
      "id": "17",
      "range": "10.152.0.0/16",
      "kind": "未明确",
      "mirror": 2036,
      "identified": 4,
      "status": "已有类型识别"
    },
    {
      "id": "19",
      "range": "10.152.4.0/23",
      "kind": "未明确",
      "mirror": 54,
      "identified": 1,
      "status": "已有类型识别"
    },
    {
      "id": "20",
      "range": "10.152.6.0/23",
      "kind": "未明确",
      "mirror": 47,
      "identified": 1,
      "status": "已有类型识别"
    },
    {
      "id": "21",
      "range": "10.152.8.0/22",
      "kind": "未明确",
      "mirror": 460,
      "identified": 1,
      "status": "已有类型识别"
    },
    {
      "id": "28",
      "range": "10.152.40.0/22",
      "kind": "未明确",
      "mirror": 1024,
      "identified": 1,
      "status": "已有类型识别"
    },
    {
      "id": "33",
      "range": "10.161.0.0/16",
      "kind": "未明确",
      "mirror": 3211,
      "identified": 4,
      "status": "已有类型识别"
    },
    {
      "id": "36",
      "range": "10.161.3.0/24",
      "kind": "大型仪器相关设备",
      "mirror": 12,
      "identified": 1,
      "status": "已有类型识别"
    },
    {
      "id": "37",
      "range": "10.161.3.2-10.161.3.10",
      "kind": "摄像头",
      "mirror": 2,
      "identified": 1,
      "status": "已有类型识别"
    },
    {
      "id": "38",
      "range": "10.161.4.0/24",
      "kind": "打印机",
      "mirror": 10,
      "identified": 3,
      "status": "已有类型识别"
    },
    {
      "id": "5",
      "range": "10.126.0.0/23",
      "kind": "未明确",
      "mirror": 1,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "6",
      "range": "10.126.1.250",
      "kind": "监控设备（未细分）",
      "mirror": 1,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "8",
      "range": "10.131.0.0/16",
      "kind": "未明确",
      "mirror": 672,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "13",
      "range": "10.131.249.0/24",
      "kind": "服务器",
      "mirror": 31,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "14",
      "range": "10.131.250.0/24",
      "kind": "服务器",
      "mirror": 42,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "15",
      "range": "10.131.254.0/24",
      "kind": "交换机",
      "mirror": 255,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "22",
      "range": "10.152.12.0/24",
      "kind": "未明确",
      "mirror": 12,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "24",
      "range": "10.152.16.0/20",
      "kind": "未明确",
      "mirror": 195,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "26",
      "range": "10.152.34.0/23",
      "kind": "未明确",
      "mirror": 83,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "27",
      "range": "10.152.36.0/22",
      "kind": "未明确",
      "mirror": 44,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "32",
      "range": "10.152.246.0/23",
      "kind": "服务器",
      "mirror": 22,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "39",
      "range": "10.161.64.0/18",
      "kind": "无线 AP",
      "mirror": 2594,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "40",
      "range": "10.161.6.0/24",
      "kind": "未明确",
      "mirror": 9,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "42",
      "range": "10.161.8.0/24",
      "kind": "一卡通系统（硬件未细分）",
      "mirror": 92,
      "identified": 0,
      "status": "有发现身份，类型待识别"
    },
    {
      "id": "9",
      "range": "10.131.0.0/19",
      "kind": "未明确",
      "mirror": 12,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "11",
      "range": "10.131.33.0/24",
      "kind": "服务器",
      "mirror": 2,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "16",
      "range": "10.131.253.254",
      "kind": "交换机",
      "mirror": 1,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "18",
      "range": "10.152.0.0/22",
      "kind": "未明确",
      "mirror": 2,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "23",
      "range": "10.152.13.0/24",
      "kind": "一卡通系统（硬件未细分）",
      "mirror": 5,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "25",
      "range": "10.152.32.0/23",
      "kind": "未明确",
      "mirror": 3,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "34",
      "range": "10.161.0.0/23",
      "kind": "哑终端（未细分）",
      "mirror": 5,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "41",
      "range": "10.161.7.0/24",
      "kind": "未明确",
      "mirror": 2,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "43",
      "range": "10.161.10.0/24",
      "kind": "大屏显示设备",
      "mirror": 75,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "44",
      "range": "10.161.11.0/24",
      "kind": "未明确",
      "mirror": 7,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "45",
      "range": "10.161.12.0/24",
      "kind": "哑终端（未细分）",
      "mirror": 5,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    },
    {
      "id": "46",
      "range": "10.161.13.0/24",
      "kind": "哑终端（未细分）",
      "mirror": 7,
      "identified": 0,
      "status": "有流量，未建立发现身份"
    }
  ]
} as const
