# -*- coding: utf-8 -*-
"""
time:2020/1/14 12:50
"""

import wx


def addRoundKey(i_state, key):
    """
    addRoundKey(state,Ki)
    :param i_state: 目前的加密信息  list
    :param key: 目前的密钥 list
    """
    for i in range(64):
        i_state[i] = i_state[i] ^ key[i]
    # print("addR的state", state)
    return i_state


def sBoxlayer(x):
    """
    S盒函数
    :param x: 输入 type: list 4位
    """
    mapping_table = [(0x0, 0xc), (0x1, 0x5), (0x2, 0x6), (0x3, 0xb), (0x4, 0x9), (0x5, 0x0), (0x6, 0xa), (0x7, 0xd),
                     (0x8, 0x3), (0x9, 0xe), (0xa, 0xf), (0xb, 0x8), (0xc, 0x4), (0xd, 0x7), (0xe, 0x1), (0xf, 0x2)]
    y = int("".join(map(str, x)), 2)
    for i in mapping_table:
        if y == i[0]:
            y = i[1]
            break
    y = bin(y).replace("0b", "")
    if len(y) < 4:
        for i in range(4 - len(y)):
            y = "0" + y
    return list(map(int, list(y)))


def pLayer(i_state):
    temp = i_state[:]
    for m in range(16):
        i_state[m] = temp[4 * m]
        i_state[m + 16] = temp[4 * m + 1]
        i_state[m + 32] = temp[4 * m + 2]
        i_state[m + 48] = temp[4 * m + 3]
    return i_state


def generateRoundKeys(key, round_count):
    """
    用于生成下一轮的密钥
    :param key:本轮的密钥, list
    :param round_count: 当前轮数, int
    :return next_key: 下一轮的key list
    """
    # 1.循环左移61位
    # [k79k78...k1k0] = [k18k17...k20k19]
    key = key[61:] + key[:61]
    # 2.对密钥前4位使用S函数进行映射
    # [k79k78k77k76] = S[k79k78k77k76]
    key[0], key[1], key[2], key[3] = sBoxlayer(key[:4])

    # 3. [k19k18k17k16k15]=[k19k18k17k16k15]⊕round_count
    temp = int("".join(map(str, key[-20:-15])), 2) ^ round_count
    temp = bin(temp).replace("0b", "")
    if len(temp) < 5:
        for i in range(5 - len(temp)):
            temp = "0" + temp

    key[-20], key[-19], key[-18], key[-17], key[-16] = map(int, list(temp))
    return key


def more_sbox(i_state):
    for k in range(0, 61, 4):
        # print(i)
        i_state[k], i_state[k + 1], i_state[k + 2], i_state[k + 3] = sBoxlayer(i_state[k:k + 4])
    return i_state


def dex_to_format_bin(value):
    """
    将十六进制的字符串转换为2进制的字符串
    :param value: 要转换的16进制字符串
    :return: 转化好的值
    """
    result = ""
    for i in list(value):
        temp = bin(int(i, 16)).replace("0b", "")
        if len(temp) < 4:
            for j in range(4 - len(temp)):
                temp = "0" + temp
        result += temp
    return result


class MyFrame(wx.Frame):
    def __init__(self, superion):
        wx.Frame.__init__(self, parent=superion, title='present加密', size=(400, 250))
        panel = wx.Panel(self)  # 创建面板.

        wx.StaticText(parent=panel, label='请输入明文:', pos=(30, 10))
        wx.StaticText(parent=panel, label='请输入密钥:', pos=(30, 50))
        wx.StaticText(parent=panel, label='暗 文：', pos=(30, 90))

        self.txt_op1 = wx.TextCtrl(parent=panel, pos=(140, 10), size=(200, 20))
        self.txt_op2 = wx.TextCtrl(parent=panel, pos=(140, 50), size=(200, 20))
        self.txt_res = wx.TextCtrl(parent=panel, pos=(140, 90), style=wx.TE_READONLY, size=(200, 20))

        self.btn_encode = wx.Button(parent=panel, label='加 密', pos=(100, 140))
        self.Bind(wx.EVT_BUTTON, self.On_btn_encode, self.btn_encode)

    def On_btn_encode(self, event):
        plaintext = self.txt_op1.GetValue()  # 返回文本框的内容.
        key_register = self.txt_op2.GetValue()  # 返回文本框的内容.
        # 转成2进制
        bin_plaintext = dex_to_format_bin(plaintext)
        state = list(map(int, list(bin_plaintext)))
        # 第一次密钥生成
        bin_key = dex_to_format_bin(key_register)
        ki = list(map(int, list(bin_key)))

        for i in range(0, 31):
            state = addRoundKey(state, ki)
            state = more_sbox(state)
            state = pLayer(state)

            ki = generateRoundKeys(ki, i + 1)

        addRoundKey(state, ki)
        self.txt_res.SetValue(hex(int("".join(map(str, state)), 2)).replace("0x", ""))


if __name__ == '__main__':
    app = wx.App()
    MyFrame(None).Show()
    app.MainLoop()
