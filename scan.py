#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyusb", "tifffile", "numpy", "Pillow", "rich", "questionary"]
# ///
"""
Plustek OpticFilm 8200i (GL128) scan & extraction tool.

Self-contained: the USB command sequence with original timing (extracted from
a SilverFast 3200 DPI capture) is embedded directly.

Usage:
    uv run scan.py [output_folder]

Requirements:
    - Plustek OpticFilm 8200i connected via USB
    - Linux with appropriate USB permissions (udev rule or root)
"""

import sys
import os
import re
import glob
import time
import pickle
import zlib
import base64
import numpy as np
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
import questionary

console = Console()

# Scanner identifiers
VENDOR_ID = 0x07B3
PRODUCT_ID = 0x1825

# Timeouts (ms)
CTRL_TIMEOUT = 5000
BULK_TIMEOUT = 10000

# 3200 DPI scan parameters
SCAN_WIDTH = 5184
SCAN_HEIGHT = 3600
SCAN_DPI = 3200
SCAN_LINE_U16 = 15552


# ---------------------------------------------------------------------------
# Embedded USB command sequence with timing (zlib + base64)
# Each entry: (delay_ms, op_tuple)
# ---------------------------------------------------------------------------

_SCAN_COMMANDS_B64 = (
    "eNrsnQd8VMX2x++9dAGDKAKCgCSUZENvikq1AJtkQ1NEikgVQaRkNxSpKiqIDRUL9t7LszdU1Gc3myCoKE0Uexes/L/n3MEX879J"
    "dpPdEDTs5z2+/vbcmbkzZ86cmXsTFla+fN2ZtiV/Rq5s7bdaL3f6DlrpX+Ov5V/ht/z2rJXnrnTVE1f6e/kr+5f4rb697OZOdqVm"
    "lZ0q/ao2qGZVt2pY+/WqOaWWVds6wKpb+cDqB9n1Fh7cqn6tBnUaOodYjazG1qFWkzpNrWa1DrOaH5JorTTFTrJNTc3+qmlS5f9V"
    "k3RIC6ul1cryNUut22ZN+2kdrI7NO1XuvLBLu66Nu605/JgjrO7WkbuP2n201cPqaQcqDao2uMaQmkPtEyqdWGV43ZNNNQnFVTOi"
    "16imo6ucYo2xxjabuGDSgtPsM+3pzoxKMyvPsrKsoBWysq3ZCXN2z909b/dZ1vyUBbsWWouaL7aW2Gc3OMc6N8K7ab3UusxaaV1u"
    "ra5+Q91brFub3Wbdbt1h3WndZd3d/nHricOftJ6xnrWeK7y4BLe4Wv7l/jp97VrFVSt2B05qGFHjnJrHFFetMTwwYWWEJaYVZShS"
    "5fQVdnpz2+/kH6a/i38vslKdCOuuFOGYVB1ojbRG7YrMT6oOtDFeGGnJDsYRN6PS/4yLb0blaEquUqRxwt+Nq0ZTcrXIjBf77b7V"
    "rd0JVnNiTOENWe70IcI4fSzHqvjzL/+zcmkBL2ng6VR2cU5lTZoSoUd1quj0f6dH7Vl1/CvSm3fyXHQ6VSt2HSvRxU2Lv7h+aWpu"
    "WlTQ/38rbfodzf9naHmmSXFL+hLikPRZ+2TSl1BkMlen2GSumJQvIdKUz4p5yldYdlcWKV9CoSmfFbeULyGalM+KW8pXfDNimPIl"
    "RJfyRb46V/ypyPciyfcSKvK9ij/FelRs872ESC9OKF/5Xmt7r+V71r6b7yXE/ZCvxPleQimO+EqZ7yVEeMRXunwvofRHfKXN9xJi"
    "c8RX2nwvIZojvhjlewmlPuKryPcq/pQi30uoON+r+FO2+V5CnC8uy3yvyfX/P99LqMj3ymO+lxD3R7re+V5CrB/pRpHvJcTlkW7x"
    "uVMMH+km7IXzvXL9SLci36v4U/E8t+JPxfPcGOZ7Hgtl25Kuvc0iPWtpH+lDuGaRGraP7uSoR7yegubPer/9K+tNKyLrbXbowibN"
    "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"
    "+nB60irm/q5tMv6j+f4L0wcynjtgWduvoY+ln/rjZ0tMfO6v61KG0wuW+CbXHmLidhcTk8XX25o+PlXXxgz8L6S+3tf0QUBjWgbx"
    "zS2zrrm/o3W9SNe6xsAHw2sTg1rO4fD+SUG9thVcDZ6m8U3GKqjlS66+EZb1Re7lIGwOhj9MljUryLixL9R1J0iMySN3zHB+Rpe8"
    "oBZ8JPpVuj5n0Jag0xN+mX74DpvRGh/dekerfTrzJkj+kGc3gqXMEVpvOnPYtbmca3dybQs4Ff2QJLed7eHG8HW6j0gnBgXVNyUX"
    "aIsu+WgdWPxO5nBaiutrsj+qYcZrKnwsnEJfzYLHwu+jT9A8PkPXl2nG1+rDDeDJKa6Pj06q+7JlJW118z93/lxhfK6d4f3hymZe"
    "iR93p13i67K2d4TPhNunuGWL706ED0hy668MHwbP15zPzS8uMr641czbtsYXzjXz/Gi4OzwS/hybN4y/Dka/Wn1E5lWQ2Ct7soDm"
    "c1eYdaoRfKnZG0sudRY8Eg7AMp6HwM2SQhrD2+maH9JcoBqcDD8PtzT6aF3DXfsbzHonfdkbfp01q3OSzD3xo0zNBWX9PwVua8qR"
    "NfxY0+b12B+eJHNL6srUMh/QfsjU3FFiZd8UsQlqvrtE1yy3zwfCI9Bl/9IHPgCWeBrUvMDtzym6joTYJ0pMDBBjQ5pz90YX379D"
    "+1/WuyD7BIm5AedAeEZSTcZ+64sy/kfS31L/Cs3D3TEUX5xm5vmNZg8sfnGZiZ994Yd1n+fmW7L+dNZzgaDuOVfBLWDJ86X8IWZe"
    "raD+JL2nPHs4eiM4F56osSCoOYLsqwJJQY0pcnZQR8t053YvkxfKeUE39Nt0XZV9Qci5RnONDO1vySk7UFdbsy9I01jg5l6jNK91"
    "x+cOuLP6jruH76x6ruasfQ0HdA0K6d5U1qwsrUv2jhmseyHdq8t+7nTdC+Tah+n8COlYnUQbjjJ7u+NM/ir9+Ros4/ar2f+1M/ug"
    "k8y9zITvM/MmS884MtSnZP7PNnXda+K85Lifa7xw+2e+Oe+Qtn1kymyt/cC+MFl8Qe5rKPu/jVtk/OXMbITuOSQWBVib3dgiviV7"
    "muvh8br+u3vaZ3WcQ7onn4aeBv9HfSeg+17Zo86Bh5q48CgsbV+se8cAvhci387Vc6lk4zt+9YWQ87XJBWQvLb67S88r3DVW1pFJ"
    "Zo94ohnnh01sTDfjsNn0q+y3R+tZoJtfBIzNpaYcaedOWM7thpt7v9rocpYie7t+uifL1b1aJ3MvffSMJaRz8kvDMm+rwRNNO8/Q"
    "8xH3LED2jhPM+N+SkuacbfbBI2DZ57+s505pOiY363lROv4dcj7UPb+7f71Vz1bS1Tdf0zOXNN07ig++Dw8x9343fD0s52z7+9JY"
    "E0LEGPGdNG3nZvXfNO3/55L6Mfcv1vH/Ci2g8VDOSdJYj0O6h18Mp5u1QO67K/yknjmlsTZLrMu1N8CLdF8tfZamMe0Sc0/LTLvG"
    "wuJfS2RfQLs6mXE7EV3861U9e3Hv4z71ozTd934F58DzTf+NNWNyiTnzyTZzKaxnECHnbfXNdMY4pGc1AVPvz/C58PnwF3p+lqbz"
    "5Aed866ep+eFbntuk/ulnWcZX3jIjNVdegaZpuPzvfp+Gvtq9x7vhOVMYT38EjzUtLM75ZxifPwY9HmwnH3lwWeac5Pd8Im6J8u1"
    "58JyhrZe/VTa4J5H3a6+k633EtQ2u+csj8JLzTnYM1pvtp4XZcHTzLnjw/B43XPn2vPh0/U85SDG/iGN/7YvTc9/7jRjO8mck90K"
    "n6vnBmH21Wl6lnoj/CQ8Xc8Cwuzb0/Rs/Bn4T3i0lhPG79P0PPcC44tyRvgT/DX6EnO2NwNerudqYft17Us5kwuzn/frOeZGeB4s"
    "bXgUvgqbFbrvDNPHfnzQ1Z8zNuu1PX7dvyyAz4XlLOtV+FRYzhoPbRHWfrrUxMn/ol+m8zBsfwu/pOcgYcbcr/H/dtOeFZrXhulX"
    "v85z6ZOz4UvgHDjV59e5ehv8HuXLuZbcyw3Y3Gxi6G44oL4WZp752YuGnO2wtGGGxvYwY+6nHplbYXsp5WSqX4dZL9JY7ySWuf0w"
    "2rRtNDxWz9PCrJVpelbyLvwOPFfXo7C9xsz5Z+EF6oPSb89vsqyJW+SfQ0z2uf4k43m/8Utpi4zVQj3fDhML3DNZadfH8Lm6Dw/r"
    "fMvSc6YwcUbmXjZxMqznv1n6vCVsX2/OEU+GH4QX6Tl82D7PnC/LWN0Gi683bSHjlq5+fCn6i+Y8UvxrGRzQc++wnhc+qH4U/utM"
    "+Vz4VngJ95oLyzmy+Pr18NXmXPBavTZD++x+eJRZI7ZpX7rn+RfD08zznEe03gxtww54I7zK9NUysw6/p+PjnslLHz+m5WfruL1p"
    "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"
    "EyWOnAIP132q28dPmfL7wL/ontjtk2X6fkzQSdI+dOt1dA8t+86g3sv5+u5IUGPoM/qOSJByWWs0zga5Jsz8TOeeXN85xtTb3eQ7"
    "ATP+I2EZr0HaD+k6/kGTX0h72sBP6N43yB6QWAbXM7FG3ompoz7yEXP/XY3/V6Elm775Q99FCbI3ddcTyb0lxl6s7+G465vMJTk/"
    "S4PfN+/DzDN9f7zJS6T+jho7wvqulsz5ARob3edenU3fN9fYEdZ3waRfDzN5VSuzRpxt1rFecBNfup6f9zRrQX9T1yh9NybIehDW"
    "d5NGGf5Ez23duHCH4a6aS6XrHG5p+kPGqq/JQQYa/5J1qp0+jw7ru2lyJn5ivvacqPHZfRZwosl9B5u171Rzbh7Qa91nSl3gh01O"
    "3Jw4cj+6jInwcyY+9oVlf94a3g/e3xfQ2CRzRZ7h9DbjIjE/07T/JROvm8A7dG8VdA7Uc5yA+vvJml8GNBZM1TU64NTVmPgUc7/P"
    "xzL+M3WvG6SNOboWyfj74LfMXqoXvBuerOteDmu7G59P0DwmgG3Q+SZRYmxAzwUWoN9u9ltp8Muw5DTHwxLD5Z2fBPgNs69KNjbH"
    "al6SQyxw9Q7wp+bcYwi8yOzVjjN9I/vzTnBvU6+sXw3Rr9S8LUffC5VxaGbaLPnL2fAW88xsEPyqybe7w3V97vl/b/g7827SKPhq"
    "8yzlFGMv+05ZvzabHKcm/IjJ4UfC6bpuhjQHkfedB6jP5hCTA/peW2v4Cn0vJMTcycEf3fOIY+DGtH+szrMc9aMTTPmvai4Q0jE6"
    "1ez5mkhd2E8xOWiu2ZvuD19izlwOg2XvK/NpLHwn3FX7ZNWLlnXCVln/t+m7YiEd85qa90gOmaPP9nqbNq4x64z4wlNmnTzC8JEm"
    "tzhd90xB4kSOPlOW8TxU/chdY7vBz+jz6qD28VX6vE18NEfXwP7qx5KDZOD/EktzdI2Qtb2jtl3GJ6h+9IJ5LthV54C8dyZtcM/n"
    "suGGZj2X556Hqi+kK3fUcUjXPKKGnnG4bXBMPpdq4uR/dU0JOb8lhu06PuEg4+bu/2TNqgN/btamfmYdlBhUT3M1eQYVZNxkr+a2"
    "LaRzT57Ju2vHgT43p5R4t9L0Z1WNQe5eWfIIny9Dc/X6Zo2TvV0dc34pfXuQ2ZdJTGll1kTZs1bTs3g3992zpkv/70qUfdCjGgtq"
    "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"
    "i7zDI+M8V9sYUh+p6kvTnxeopb6bpmfs92v9fj3bl7xQ7OVnvmuYczXJEWTtbaMxLaRj6NN4FWScZW/knnvJnu8on3vWKGvEDylu"
    "/1Ux795KfnZ7opzbpGnOJ+UcYcbkA50PafosW9p8us/NcX5KdNs51+SI0k898p3bjdCfF5P5ma453Fq1kXci3H2hvI8SMnulj/R5"
    "kbsnHmZyqwQ910hT++/MvZxu/OsJfUc8qM+4Vpnzuf8muvnfcDPmMi7TTZvnGt+Rs+Ma+u520PlR41Ea/e3mwb/rO99uv7X3uXNU"
    "4shwk7utSWzF3n+rvv9zpC9d9+epZo+15zws1fh6kp5LuXu1A0ydc0zZovcx+fBb+c4CZRxmmXjRyJxLNkpy58MEcy7VysyfmnqO"
    "7d6T+GCWz80ppQ9+SXH9foOu4W4f7G/OPVNNbpqN3s6cNXbzuff9tumDzmb+j/NJruaeTf5h9poyP2f45L126Q/3zDfd7Fmm+lzf"
    "kbPp1j7X/gBznitnHK8ZfYyZzx9onuqOuayn3U3s3c/n7k0ltvfQtdW9x+5mzKvq/ijNmW3aOcX44y+m/Pmm/JvNtbckuvuFo00/"
    "9PT9X3tvHu9T+fX/v/f2PscQGaNBEWfifRxDiIwl5YxUKiklZWgQDeccc8gUpYxlSDJEhUITGkQlaXqfY2hASUSUqGiS73Ota/W5"
    "u+/v/nw+7vt+/H738N29/3n2Out97eta17rWNey933J0n/2H5Zq+ds5TycZHou59c/R88W3LZW10zd2bsT9Mz3+qxXK0/xsmuTXw"
    "AFvD3/IXH8j+4war1xFb87eSZ5FtvyD54pg+Z+7qda6VKXNRvsVoCctvMk6O6DzmfLlBc1eOrilT9KzJrUfW6/mPvN+Qr3UYHhM/"
    "uXVs/ZizKalrZre++XPc5sMSy3m6b3fryzzbh5e2tXF725sM1PnIlSnrudttL7OvrpsXpF0vwUlm3z7m9nCS52+3cztZ116l55Hu"
    "DP0Qe/LBdvbxq50jSp6StVJvO5//ua6bk3+xtUlnm/MbGKfovjBL80VXO1vrajlI5vkeVodmMXfmc7o+H+HOr/bbudkt1pZb4Jus"
    "zOYxd17QLOkH8v93mv+vQCu0uG8AD7VYvxtuaHlGbK61554O077RFlvd0W+2HHEQ/Qqbu55BH2g5eaOdw3maDzP1WacPsLkavtxs"
    "jtbN1PIv0uf2MvW7e2rLuwmZGtNVdN5xNj/rfJ6pcb9L83mm9pvkwG7wMBvnN8CtbV4dCg+w3CTnbR0sf1Uz/0kO72Hn5KX0ucN/"
    "sbnazu3O0fGWpc9tnWNnb/0sxjujX2m+l/PFQXavZGjMnWvvqu3sZe19oLbrq966JpbzgiyN2ZidlfbUPYjzbT/dR0iuzNJ90yd2"
    "zjvb9kFNtL+cvhz9Vtsrd0KX/YWsp/bWzdLndaSeXkxiU85xoqz9Nmn+b2R7ox165uTONw/YWW2h7aXnqm/ydf6sZfa+nZPeZfcC"
    "Inruma95pKKVc0zPFCSO8/XssAO8AL7C2vqw7e1e0Ha7WHg65uJI9mHvaezIdeNq38/2Ao31nFRiRPYsWbpmkmcQJNa72P1FGRtj"
    "tMy4nreO0hiJs9518Sjnkbkxd13Z1zwQc+fgO/U80t0nOVw7rmeyd+sYk2cE3Dj04QKrw+n6/GeWv1bzfFzHyhCNo7ie2y7V9YI8"
    "T+e+K/ev+9t9GDmbaKU+dM98xGLunP977CWOOtqZZarlgm/QJRc8bG3x7IxY9lmXwzLHfQ0PiLnYFJa+cM/WuL3pCJ2LazD2Z62T"
    "/d8m3XNKLorre1U55ku5x/KYznVxPYtw5zayX3Q5RPqkno3/dbpvc3XcB1ewHCv+qGrnlV9pvbJ1bJyqzwW4c3XZ891kdZS+Ot/O"
    "26Vvt2Ij554bra3tdL5w+/N+dnY80O7zvGPt7mH9U2z5SPRtdd34rKRntW7MS31W232SqD6bku2Pt3NkObefbvU5z/y9C/tLudYE"
    "O7++2PZt0ie/630kd/5/l+0Li2u7c5PbLOf/qu+1ufWl7FOqWv1l3zzB+rONnUcXw3LOmmh8vp1rZyS5M6X2tgYdamefkmsujGXp"
    "Plhy3GjzQ1l9ri1L++7H2m5uelT9v5D8X3mfjP/Wdv9kta45sjQn/2Dj7V4rr4Te9yzUfkjVeC3UM61TbG75VM8W3H1MiRG5ByLv"
    "bcqaTO5XyPuTsgZqAcsebnlteSY3S+Oups1jbW1ddYaNq6iu1VybZA0subq77QVlHNazXP1T3Sx9FkjW8CP0u4U63z5YN0vf2//z"
    "3li+Pvfi7gXLcxVVdU7J0t8pOFDbnRHfZvU8pGPC7Vmr6ZxfqGdWa9DnyrsDtd258zh9Dsed7cvzTnLucK7Zf1vbvaco5Xj6LGC2"
    "Pv9zws4U5Jny9XY+196eoahjdfjY9rjyLJPMdwmxbH2uXc4mMm1PnGTn0XfoM0Ju7TDd9otyRiA5aKp9t6H1f1M743iy9oVrI5E7"
    "v/jz/s+Ntge6KOa+t8v2/93tfFbORv7c0za39UdE1xzuXOB4bccyBmReknXSQlu317DvbrI1UGd7prGl7v/dWkPuaTxoc7vsz2+x"
    "uLge/TnbUzaNuXcmL0ly5zYDrT/7absL9Xxb9vOy15S57n54lu1ZW+tYLdQ5tg9rxAX6HJasTWXMF2q7Slq/1bKzxj/3u1fF3Lu9"
    "1e1+h7z7cprdg5azjBJ27+s667db1YeFug7+Xe9xFOo9iFjM9dWu2i5H3GbPRKTA62yvdK3lFz/J3Qu43NZ8l9g9ggpW/1ttbJeP"
    "ufejZW+VHXPvX8u4uRx+0u5Nyn59nj2PKOXcpWcB5++JRHbr+r8glqPvB6TrWXSOvn8qLPcxFpqfZJ8s7zHI/Z8OauPWZLL+76q/"
    "LeLOCOS9qua2Jxtk6+FLbE+Tof3s9hHV9bkEZyNjezS8zGIn08qXM2jZSz1lPrhZ6+OesW6o5xhu3fZgzO0povZ+Qx+r28yYe+5U"
    "9ho36Pscbg861fTEJKcPtvtzI2PuGVQpp2NM3hdxa/v25u9k3SPIu8OuH66L5ep8UV77Vt7tcNcdBj9gfXtc3y9ybXwQXeosa7W+"
    "MfeOwyEdc+7sQO4RvxJzz6nvrO3efZloz6ON5Lqv2JlVW/Ph73p+kav1Ka19Ie+FuLjIg5+256mEn4DlnsL98JM6tjox9gv0+c/7"
    "Yrm61j3d3sOYbmX0jrnry3nlBHiaPVt+CTzJrnmT+U+e1ZoSy9X11lm6B84lT7rnsPbY82XiVzlr+M72iOfDc+zemPhvpPXzmfBi"
    "e976+liuznvl9Z5pLvnQ3d++2Pwn1x0O32P7V+lPWQteneT82s9yU6lYrt6rdfey3PPW6RYjT9mZb7NYrq7/E3WucXHUTe/DOx/L"
    "WVCW+ae37n2cjzP0vn2uxmyGnpW4PozYtcbbudDlsVwd21db+TdaTq5sY/WSJHfva4jdF5TxMUmfxZX9l4s7mYPugefDLZPcu9tz"
    "7XmNZ2zcpOpeJkd9dZmN4/kWj3Im0l2fv2z/eiTS6HNZ/0l+kHjtlSRrqRz16/n6bKnkDfeuRm0bP3JfoH7MnWO2h2XvvVXHoZzD"
    "un67C06zvpU+edLKjyW5cwSZ82vbPbwx9g5PIvaPW9/+Bj9kz/Avgx+0M6I71ff5mkvv0lh39/Ca63Xz9bmn1nrdfM1718Iv2HM+"
    "SfAKe65msdnfbv220vbn/YwzLZYlRuR9wTts3F6ve5Mc7c+rrR9WWszKswxP2J5/CPyaPVPyMjzH4usG+Bl77kDO1p6y59TvNp9k"
    "4bfZ5v+OSXF9tvI+e7fmAXiF5oK45vyl1l8PMF8s0NiJk/+ztY/kGe3HTJe9xhCzH231XKbrxZfI/8PXyvi/2fpTnm/YZbY15Bl1"
    "+HnL4V30NwLcmEzRe13ujHCsxZb4YCK81s4LpJ8X2bnAzTpnunNbiVHZUwzVvaA7q5e160L0nfRJVpI7k3vQ+mcINqvha/TZu2zq"
    "nq/zs6xB5sKtNAdl+2/CveTdGFj69nK7H/k03Fb7XNYC+frsqMztI/X5dTkvyNZ+kHe75D7JG/pbQ+7+zAw7R+hl94Iq2jriRRvn"
    "M+HXrc+fgAv0fSfnn1F2liF7k6n2HFGmffcC9ZWUma9+uxGebc+dTbZnNaT+9+kaKl/fEXrRzsGa6hmuu9eYrW2Uudv5Tcb5EMvz"
    "S+yMe6C1cYi9L1LB+iU5aTBjv1Dzfz+05VbfnnbGKnPde3xvjuXtPvDz9l6KjOdXrbzBupZycSHzzwemJ9lY0vsVliev1Xq5XNrD"
    "xt5zNh4+gufZXNfYck0djZFc3V820PVNrvZDa5tfptt4nheT9wLdO0IT7btVdVy5ee8K7dtcjcFM9Z+bvxrYHDfC+mS5zSP6XqvN"
    "kz30vM3l8+72XujTdlZ/o+U4yUdX44cX7azufsubKdYnH9l1G1sOP93GzSf67oOsNXL89bD025fwBnsXtLWelRfqdz/SOcK9Ky1r"
    "uzVwI3nmR8eNe0+lq63XZByshT+2d1Z76Dzu1spP6zwua+gs9v53f+7O/3KJdfeOjczJ79s7x0t1TivUGB2vObNQc5rMYw/bO6Ly"
    "vuhYe159hebwQs298+GFNqd1tvyZaXWR9/yv0jGfy5qmUO+BXKfPjri6p8KL4GbWJ1/aHqu/9kmh5mGJhan23rbE3YdwGT2nyvXf"
    "1ndHZOzl6vv5LS2fP6L7s7jG1zJ7r6Wl+Ubez/g5lqvjIEfnQbcu6ABvtrbIewpz4Nd0jo3r/LLW3pscG8vV+3ySQ1+weVhy9Z3w"
    "SzoO4vgzR9f5fZPiem4/2L7b0ljOfwopZ4PO7XHvEVje1Zwq74hY3WKa2904k2flbrH7F/Jew73w6/ouWJx5x40zeb/oeTgh2b0T"
    "29/WcZcmXcbYv+gNmf+72TpP3nW54W/ribjuPw7Zu6D7bb66QN/JdZxlfbXJ1uFN1K9u3I6ydkgstLP5vLE+0+LWunLutchsZK6b"
    "bG1qa/05wd41aWJzShdr3xGbD2UP9LKdaXW0nCZ1e9zm2Nrosm97y3KE5Lg37N0uuR/2to1nT+8XuHnyo1i2rpkGqZ+y/Xfs3dcf"
    "4dd0jxD3Btle7SY9F8rW/CV+XQL/ZDYr7HlBeSfn81i25hp5d2iCzl8F+l5TVzuHu86eEXzY3omReftlXQe5ZyUftHcu+tpc0wAe"
    "BT9Ozpc5WuadJ/Q9yLg+O/SI6fdoOfn6LvAt8Bp9dlRiP9svhjsmvcX6P+Ur6f9FaE+iydnSwzof5qsPhuueT54nipNPXHlDrbzJ"
    "OvfGdQ//iV0nU9uarz6QZ512wYf03M7Zt5Z3b2PZetbd0c7PluhziXE9X1ip83Nc9/lrdD3nzttkPpRxJXvme3U+j+ucvFDnvbi3"
    "QM8C8smNbg00X5+NlfHmfHOT1bO3zp9xb6v6O1/fHWukZxD55Hz37OgK82Vv84mspa7XtUOBvrclz4Xcos+7x7238M90fVYrTt7J"
    "0TlczgXzND+7tvTRvO1sZH0k61EZZ/PgGTrPx/U5xSet/tJv22DJEXJ/aamVORv+0Pxwt8advB/rntFZBMs7dJfrXOOe/5pv64WW"
    "tk59RvvXrXGe1+dCG5P/r9H8v8jOZNsnuWc4F9m9upbW1mzNS26tdoWOq2zNLenWz3fZu4tLtR0u53SysSHv1V0Zc/cUJe7PtXF7"
    "m5UjdZe9xnL0z+E7bK35oK3zpP/36v08V4dRsOSCty3WM/S72f6jsOSCcTqu3LOpN5i/2+heLdvfaOuwkboezdf8nGWxNtDiUdZk"
    "5TX3ye+C5bMHdOet0+1aaenOf+KTO2xtJ7lspa4XXXxdbeNZ3ucbqmuofM0vQ2PybEe+viP4vq135d3EmrqGztccPkzX4i4G+1oc"
    "yThL0bW4K2eKnhHla46rTH326P2UuK7XZDzdYuu1l3X8yXlHtr8ZTtN9pIvxi5NG7o5Eznxd+n++nmPm4/Mi5opscnK+rnvkWbci"
    "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"
    "BDwaFv17bavTz40x/8Dj4Oox8X1HLf+Y5MzGHf374VT0Jegr4MSYtLuj/6H5/hh8L3xI+7aj/zjcGn3veZ38mfBF8GxY2vE7NsMa"
    "d1Lfn4H+A/q35oM66C/DbWLSrk7ah4fVf538sXA79E3oc+Bv0FujF8Hd0cdx3RmxwbS/2LsD/TG4LPwp9k9q/2z2CmnLK+hV4Y3o"
    "y+BUeCZ6avpg/1T4PcoZhZ4J10LfAzeKbfH6Ueb98Dmw1LMz9tnw6Y2ljYPx+RavPlwafRA8nXLWobeGC9CPUwf57k9c9xn4Ergx"
    "uvgwBmdyrYNwBtwCPgZfCb+Pzc+U0yN2/mv15jdZs+i1qWOnjpk6rUTEi8h/2eX73J7tXxTxI5Et3jl88Wwq8GPdLV4b+A++2DS2"
    "1YtRyI9wS/j8xpf5jbC5Du6GzanpQ3DEVm8RgXYq+iQ4Ha4C3xTb5lXH5hxsMtCPUvnGcDZ8BmWWgevBKZR5NnwfPBl9aWyIPxge"
    "zXfX05A7ceal2IhzhqI3bNxZr9sZfqfxFX5i+jB/Kte6sfGVfmV4onZcF/+n2Ag/PxYJ/zup/zQwsiNpfbzstdllsydmn57t3fMX"
    "KZo70cut5WX7Kpb/FzG7lmmBhn+K2RNza533L1o0uy3afdmRdv551abe828uXdMuXf6ff7nG3/3yvzJMvMzvFrk+7WSNS2Bca+pf"
    "6/APjKMnX7L/UZmTNIyXObnL+0UnWWL0i8iuPv/I038x/fKU3ZGTLPWrU/Z4J2m697SvZ5yk6b7T9s88ufZHv6l5oNFJlnqw5rfn"
    "naQHvqt7aNNJlvp93cPvnaTpkSY/3HySFfixyU89T7LUo22OHT/JqPo54e969d1/kc4N+m7bFp5XK3pRQodWkdZ3tBn1ZGRRZHHk"
    "qcjQyLCm9z43PDKi7cjIfZFRR0ZHxtQZe1e6X6/L2cOr11wQWeg9HXnG809fdpIB5T977z/30Mhsr12pyNpIBZm4/n65f5vbnq9x"
    "otKT5Y+X+6bsuWUnnFL2lCfLdCzjlXm99KjSHUufU/pwqXdKzSt1b6nupS4slVyqdKnvS35S8o2SS0s+WnJUyTtLdi/ZsWTrkvVL"
    "1ihZoaRf8qfEfYmfJX6YuD7xpcQliU8kTk98IHFk4oDEfom9Ersldk7MTmyX2CLxvMT0xKTE6omnJZZLLJkYSfwl4YeEgwl7E75I"
    "+CRhc8IHCe8krEt4NeGlhBUJSxMWJcxLeCzh0YQpCRMTxieMSRiRMCRhQMLdCf0SbkvoldAj4YaErglXJVyRkJeQnXBpQruEtgkt"
    "E5olNElomJCRUDchNaF2wrkJZyecmVA1oUpChYRyCWUSSiZEE7yEP6K/RX+OHo3+EP0++m30m+i+6J7o7ugX0R3Rz6IfR7dGi6Px"
    "6AfR96LvRjdE34qui66NvhZdE10VfSn6QnRl9LnosuiS6NPRxdGF0QXRJ6KPR+dEZ0VnRB+JTotOjU6KPhydGH0gOj46LjomOio6"
    "Mjoiem90aHRwdGB0QLQgek/0ruid0X7RvtHbo7dGb4n2jvaM3hztEb0xekO0W/S6aNfoNdGro1dFO0eviF4W7RTNi+ZGs6NZ0Q7R"
    "S6OXRC+OtoteGG0bbR1tFW0ZvSDaPHp+tGm0SbRxtFG0YbRBtH60XjQ9GovWiaZFU6Mp0aRo7Wit6LnRGtFzomdHq0fPip4RPT1a"
    "LVo1elq0SrRStGL0H81tf42oiPeXiCofRlQYUf/xiNJkVv4fzo3/Nt/W+L+l8qEUSqEUSn93Xeb7pU5yV8PCLdLG+6ebrb+3z/uv"
    "Ef/a0NP/WTIN3nr+/SJTcMl5bTr4p7tVbPWa4yMTIg9EHoxMjDwUeTgyKTI5sizy7Il/7t9/74J0Z9XPEtsmDIsmRpeXuLNE6xJV"
    "ShzxN/ur/fn+RH+If5t/nZ/nX+g38ev6Nf2qfjk/wT/u/eR9533tfeF96m32PvA2em96r3urvRe85d4Sb7G3wJvrPebN8KZ5k72H"
    "vAe8cd5ob6Q33BvqDfIKvXzvLq+/19e7zbvF6+Xd7PXwunvXe9d5Xb0u3lVeZ+9y7zKvo5frZXtZXgfvEq+91867yGvrtfFaeS29"
    "Fl5zr5nX1GviNfbO8xp6Dbz6XoaX7sW8ul4dL81L9VK8ZC/Jq+Wd69X0anjneGd71b2zvDP5nOGd7lXzqnqneVW8yl4lPhW9Cl55"
    "71SvHJ+y3ike6yavtFfKK8kn0UvwonxKeD4fz4vwORH5g8/xyO98fuPza+QXPj/zORY5yucnPj/y+SFyhM9hPt/zOcTnOz7f8jnI"
    "5wCfb/js57OPz9d89upnD5+v+OzWz5d8dvH5Qj+f89mpnx18tuvnMz6f6ucT/Xysn218tupni34266dYP0X6ievnI/383eVD+X+w"
    "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"
    "BzWNAhQ="
)


def _load_embedded_commands():
    compressed = base64.b64decode(_SCAN_COMMANDS_B64)
    blob = zlib.decompress(compressed)
    return pickle.loads(blob)


# ---------------------------------------------------------------------------
# USB
# ---------------------------------------------------------------------------

def find_scanner():
    import usb.core
    import usb.util

    dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
    if dev is None:
        console.print("[bold red]Scanner not found.[/bold red] Is it plugged in?")
        sys.exit(1)

    try:
        mfr = dev.manufacturer or 'Plustek'
        prod = dev.product or 'OpticFilm 8200i'
    except (ValueError, usb.core.USBError):
        mfr, prod = 'Plustek', 'OpticFilm 8200i'
    console.print(f"  [green]{mfr} {prod}[/green] (bus {dev.bus:03d} dev {dev.address:03d})")

    if dev.is_kernel_driver_active(0):
        dev.detach_kernel_driver(0)
    try:
        dev.set_configuration()
    except Exception:
        pass

    cfg = dev.get_active_configuration()
    intf = cfg[(0, 0)]
    usb.util.claim_interface(dev, intf)
    return dev


def replay_ops(dev, timed_ops):
    """Replay USB ops with original pcap timing."""
    total = len(timed_ops)
    expected_bytes = 225_000_000

    raw_data = bytearray()
    errors = 0
    consecutive_br_fails = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Scanning[/bold blue]"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[dim]{task.fields[size]}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=4,
    ) as prog:
        task = prog.add_task("scan", total=expected_bytes, size="0 MB")

        for i, (delay_ms, op) in enumerate(timed_ops):
            kind = op[0]

            # Sleep the original delay (skip tiny <1ms, cap >2s UI interaction gaps)
            if delay_ms > 2000:
                time.sleep(0.1)
            elif delay_ms > 1:
                time.sleep(delay_ms / 1000.0)

            try:
                if kind == 'CW':
                    _, bmRT, bReq, wVal, wIdx, data = op
                    dev.ctrl_transfer(bmRT, bReq, wVal, wIdx, data, CTRL_TIMEOUT)
                elif kind == 'CR':
                    _, bmRT, bReq, wVal, wIdx, wLen = op
                    dev.ctrl_transfer(bmRT, bReq, wVal, wIdx, wLen, CTRL_TIMEOUT)
                elif kind == 'BW':
                    _, ep, data = op
                    dev.write(ep, data, BULK_TIMEOUT)
                elif kind == 'BR':
                    _, ep, expected_len = op
                    result = dev.read(ep, expected_len, BULK_TIMEOUT)
                    raw_data.extend(result)

                consecutive_br_fails = 0

            except Exception as e:
                if kind == 'BR':
                    consecutive_br_fails += 1
                    if consecutive_br_fails >= 3 and len(raw_data) > 10_000_000:
                        break
                else:
                    consecutive_br_fails = 0
                    errors += 1

            if len(raw_data) > 0 and i % 50 == 0:
                mb = len(raw_data) / 1024 / 1024
                prog.update(task, completed=min(len(raw_data), expected_bytes),
                            size=f"{mb:.1f} MB")

    console.print(f"  {len(raw_data):,} bytes received", style="dim")
    if errors:
        console.print(f"  {errors} non-fatal errors", style="yellow")
    return bytes(raw_data)


# ---------------------------------------------------------------------------
# Image extraction
# ---------------------------------------------------------------------------

def build_col_map():
    col_map = np.empty(SCAN_WIDTH, dtype=np.intp)
    for i in range(SCAN_WIDTH):
        if i <= 2058:
            col_map[i] = 2058 - i
        else:
            col_map[i] = 7242 - i
    return col_map


def extract_image(raw_data, output_file):
    raw = np.frombuffer(raw_data, dtype='<u2')

    height = SCAN_HEIGHT
    n_lines = len(raw) // SCAN_LINE_U16
    lines = raw[:n_lines * SCAN_LINE_U16].reshape(n_lines, SCAN_LINE_U16)

    odd_lines = lines[1::2]
    n_odd = odd_lines.shape[0]

    R_START, G_START, B_START = 129, 141, 153

    max_needed = B_START + height
    if max_needed > n_odd:
        console.print(f"  [yellow]Warning:[/yellow] need {max_needed} odd lines but only have {n_odd}")
        height = n_odd - B_START

    col_map = build_col_map()

    R = odd_lines[R_START:R_START + height, 0::3][:, col_map]
    G = odd_lines[G_START:G_START + height, 1::3][:, col_map]
    B = odd_lines[B_START:B_START + height, 2::3][:, col_map]

    result = np.stack([R, G, B], axis=2)
    console.print(f"  {result.shape[1]}x{result.shape[0]} @ {SCAN_DPI} DPI, 48-bit RGB", style="dim")

    import tifffile
    with console.status("Writing TIFF..."):
        tifffile.imwrite(output_file, result, photometric='rgb',
                         resolution=(SCAN_DPI, SCAN_DPI), resolutionunit=2)

    _save_preview(result, output_file)
    return result


def _save_preview(data, tiff_path, scale=2):
    from PIL import Image

    preview = data[::scale, ::scale, :].astype(np.float64)
    for ch in range(3):
        p1 = np.percentile(preview[:, :, ch], 1)
        p99 = np.percentile(preview[:, :, ch], 99)
        preview[:, :, ch] = (preview[:, :, ch] - p1) / max(p99 - p1, 1)
    np.clip(preview, 0, 1, out=preview)
    np.power(preview, 1 / 2.2, out=preview)
    preview_8 = (preview * 255).astype(np.uint8)

    preview_dir = os.path.join(os.path.dirname(tiff_path) or '.', 'previews')
    os.makedirs(preview_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(tiff_path))[0]
    preview_path = os.path.join(preview_dir, f"{base}_preview.png")
    Image.fromarray(preview_8, 'RGB').save(preview_path)
    console.print(f"  Preview: [dim]{preview_path}[/dim]")


def _next_scan_name(folder):
    """Find the next scanNNN.tif name in folder."""
    existing = glob.glob(os.path.join(folder, 'scan[0-9][0-9][0-9].tif'))
    if not existing:
        return 'scan001.tif'
    numbers = []
    for f in existing:
        m = re.search(r'scan(\d{3})\.tif$', f)
        if m:
            numbers.append(int(m.group(1)))
    nxt = max(numbers) + 1 if numbers else 1
    return f'scan{nxt:03d}.tif'


def _browse_gui():
    """Try to open a GUI folder picker. Returns path or None."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        path = filedialog.askdirectory(title='Select scan output folder')
        root.destroy()
        return path or None
    except Exception:
        return None


def _show_folder_info(folder):
    """Show info about existing scans in folder."""
    tifs = sorted(glob.glob(os.path.join(folder, 'scan[0-9][0-9][0-9].tif')))
    other = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]

    if not other:
        console.print(f"  Folder is empty.", style="dim")
        return

    if tifs:
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="cyan")
        table.add_column(style="dim")
        for t in tifs[-5:]:  # show last 5
            name = os.path.basename(t)
            size = os.path.getsize(t)
            table.add_row(name, f"{size / 1024 / 1024:.1f} MB")
        if len(tifs) > 5:
            console.print(f"  ... {len(tifs) - 5} earlier scans")
        console.print(table)
    console.print(f"  {len(other)} file(s) in folder, {len(tifs)} scan(s)", style="dim")


def interactive_setup():
    """Interactive folder/file selection. Returns output file path."""
    # If a CLI arg was given, use it directly as folder
    if len(sys.argv) > 1:
        folder = sys.argv[1]
    else:
        console.print()
        choice = questionary.select(
            'Output folder:',
            choices=[
                questionary.Choice('Use ./scans (default)', value='default'),
                questionary.Choice('Type a path', value='type'),
                questionary.Choice('Browse (GUI file picker)', value='gui'),
            ],
            default='default',
        ).ask()

        if choice is None:  # Ctrl+C
            raise KeyboardInterrupt

        if choice == 'gui':
            folder = _browse_gui()
            if not folder:
                console.print("  GUI picker not available or cancelled, using ./scans", style="yellow")
                folder = './scans'
        elif choice == 'type':
            folder = questionary.path(
                'Path:',
                default='./scans',
                only_directories=True,
            ).ask()
            if not folder:
                raise KeyboardInterrupt
        else:
            folder = './scans'

    folder = os.path.abspath(os.path.expanduser(folder))

    if os.path.isdir(folder):
        _show_folder_info(folder)
    else:
        console.print(f"  Creating [cyan]{folder}[/cyan]")
        os.makedirs(folder, exist_ok=True)

    name = _next_scan_name(folder)
    output = os.path.join(folder, name)
    console.print(f"\n  Next scan: [bold green]{name}[/bold green]")
    console.print(f"  Full path: [dim]{output}[/dim]\n")

    return output


def main():
    console.print(Panel(
        "[bold]Plustek OpticFilm 8200i[/bold]\n"
        "3200 DPI / 48-bit RGB",
        title="Film Scanner", border_style="blue",
    ))

    try:
        output_file = interactive_setup()
    except KeyboardInterrupt:
        console.print("\nCancelled.")
        sys.exit(0)

    with console.status("Loading embedded scan commands..."):
        timed_ops = _load_embedded_commands()
    console.print(f"  [dim]{len(timed_ops)} operations loaded[/dim]")

    console.print("\nConnecting to scanner...")
    dev = find_scanner()

    try:
        folder = os.path.dirname(output_file)
        current_output = output_file

        while True:
            console.print()
            raw_data = replay_ops(dev, timed_ops)

            console.print("\nProcessing image...")
            extract_image(raw_data, current_output)

            console.print(Panel(
                f"[bold green]Scan saved:[/bold green] {os.path.basename(current_output)}\n"
                f"[dim]{current_output} ({os.path.getsize(current_output) / 1024 / 1024:.1f} MB)[/dim]",
                border_style="green",
            ))

            again = questionary.confirm('Scan another?', default=True).ask()
            if not again:
                break

            name = _next_scan_name(folder)
            current_output = os.path.join(folder, name)
            console.print(f"  Next scan: [bold green]{name}[/bold green]")

    except KeyboardInterrupt:
        console.print("\n\nScan interrupted.", style="yellow")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]ERROR:[/bold red] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        import usb.util
        try:
            usb.util.release_interface(dev, 0)
        except Exception:
            pass


if __name__ == '__main__':
    main()
