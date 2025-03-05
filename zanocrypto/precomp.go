package zanocrypto

import "github.com/ModChain/edwards25519"

// Global constants

var (
	C_point_H = &edwards25519.ExtendedGroupElement{
		X: edwards25519.FieldElement{20574939, 16670001, -29137604, 14614582, 24883426, 3503293, 2667523, 420631, 2267646, -4769165},
		Y: edwards25519.FieldElement{-11764015, -12206428, -14187565, -2328122, -16242653, -788308, -12595746, -8251557, -10110987, 853396},
		Z: edwards25519.FieldElement{-4982135, 6035602, -21214320, 16156349, 977218, 2807645, 31002271, 5694305, -16054128, 5644146},
		T: edwards25519.FieldElement{-15047429, -568775, -22568195, -8089957, -27721961, -10101877, -29459620, -13359100, -31515170, -6994674},
	}
	C_point_H2 = &edwards25519.ExtendedGroupElement{
		X: edwards25519.FieldElement{1318371, 14804112, 12545972, -13482561, -12089798, -16020744, -21221907, -8410994, -33080606, 11275578},
		Y: edwards25519.FieldElement{3807637, 11185450, -23227561, -12892068, 1356866, -1025012, -8022738, -8139671, -20315029, -13916324},
		Z: edwards25519.FieldElement{-6475650, -7025596, 12403179, -5139984, -12068178, 10445584, -14826705, -4927780, 13964546, 12525942},
		T: edwards25519.FieldElement{-2314107, -10566315, 32243863, 15603849, 5154154, 4276633, -20918372, -15718796, -26386151, 8434696},
	}
	C_point_U = &edwards25519.ExtendedGroupElement{
		X: edwards25519.FieldElement{30807552, 984924, 23426137, -5598760, 7545909, 16325843, 993742, 2594106, -31962071, -959867},
		Y: edwards25519.FieldElement{16454190, -4091093, 1197656, 13586872, -9269020, -14133290, 1869274, 13360979, -24627258, -10663086},
		Z: edwards25519.FieldElement{2212027, 1198856, 20515811, 15870563, -23833732, 9839517, -19416306, 11567295, -4212053, 348531},
		T: edwards25519.FieldElement{-2671541, 484270, -19128078, 1236698, -16002690, 9321345, 9776066, 10711838, 11187722, -16371275},
	}
	C_point_X = &edwards25519.ExtendedGroupElement{
		X: edwards25519.FieldElement{25635916, -5459446, 5768861, 5666160, -6357364, -12939311, 29490001, -4543704, -31266450, -2582476},
		Y: edwards25519.FieldElement{23705213, 9562626, -716512, 16560168, 7947407, 2039790, -2752711, 4742449, 3356761, 16338966},
		Z: edwards25519.FieldElement{17303421, -5790717, -5684800, 12062431, -3307947, 8139265, -26544839, 12058874, 3452748, 3359034},
		T: edwards25519.FieldElement{26514848, -6060876, 31255039, 11154418, -21741975, -3782423, -19871841, 5729859, 21754676, -12454027},
	}
	C_point_H_plus_G = &edwards25519.ExtendedGroupElement{
		X: edwards25519.FieldElement{12291435, 3330843, -3390294, 13894858, -1099584, -6848191, 12040668, -15950068, -7494633, 12566672},
		Y: edwards25519.FieldElement{-5526901, -16645799, -31081168, -1095427, -13082463, 4573480, -11255691, 4344628, 33477173, 11137213},
		Z: edwards25519.FieldElement{-3837023, -12436594, -8471924, -814016, 10785607, 9492721, 10992667, 7406385, -5687296, -127915},
		T: edwards25519.FieldElement{-6229107, -9324867, 558657, 6493750, 4895261, 12642545, 9549220, 696086, 21894285, -10521807},
	}
	C_point_H_minus_G = &edwards25519.ExtendedGroupElement{
		X: edwards25519.FieldElement{-28347682, 3523701, -3380175, -14453727, 4238027, -6032522, 20235758, 4091609, 12557126, -8064113},
		Y: edwards25519.FieldElement{4212476, -13419094, -114185, -7650727, -24238, 16663404, 23676363, -6819610, 18286466, 8714527},
		Z: edwards25519.FieldElement{-3837023, -12436594, -8471924, -814016, 10785607, 9492721, 10992667, 7406385, -5687296, -127915},
		T: edwards25519.FieldElement{-20450317, 13815641, -11604061, -447489, 27380225, 9400847, -8551293, -1173627, -28110171, 14241295},
	}
)
