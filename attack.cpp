#include "globalvars.h"

using namespace std;

u64 n;
string fn;

IppsAESSpec * pCtx1;
IppsSMS4Spec * pCtx2;

u8 m[16];

unordered_map<data_t, u64> G1;
unordered_map<data_t, u64> G2;

vector<vector<mb_t>> M1S;
vector<vector<mb_t>> M1L;

vector<vector<mb_t>> MS;
vector<vector<mb_t>> ML;

vector<mb_t> MJoux1[2];
vector<mb_t> MJoux2[2];

vector<mb_t> Me;

u64 q;
mb_t m_bar;
u64 d2;
u64 dr;

data_t IV = 0x31415926 & mask;
mb_t *OM; // Original message
data_t *OMS; // Internal States in chains to processing original message

mb_t *SM; // Seconde message
data_t *SMS; // Internal States in chains to processing original message

u64 functionCall;

unordered_map<u64, vector<mb_t>> DT1;

void randmblock(u8 mblock[16])
{
	while (0 == _rdseed64_step((unsigned long long *)&mblock[0])) {}
	while (0 == _rdseed64_step((unsigned long long *)&mblock[8])) {}
}

void zeromblock(u8 mblock[16])
{
	((u64 *)mblock)[0] = 0ULL;
	((u64 *)mblock)[1] = 0ULL;
}

void init_func()
{
	IppStatus status;
	int keylen;
	int ctxSize;
	Ipp8u pKey[16];

	memcpy(pKey, m, sizeof(pKey));
	keylen = 16;
	initfunc(AES, pCtx1);
	initfunc(SMS4, pCtx2);
}

void end_func()
{
	endfunc(pCtx1);
	endfunc(pCtx2);
}

data_t Zipper(mb_t * M, data_t * S, u64 length)
{
	data_t chainState = IV;
	for (u64 i = 0; i <= length; i++)
	{
		chainState = h1(chainState, M[i].block);
		S[i] = chainState;
	}
	for (u64 i = 0; i <= length; i++)
	{
		chainState = h2(chainState, M[length - i].block);
		S[length + 1 + i] = chainState;
	}
	return chainState;
}

data_t cycleSearch(func_t func)
{
	data_t start;
	while (0 == _rdseed32_step(&start)) {}
	start &= mask;

	data_t tortoise = start;
	data_t hare = start;

	while (true)
	{
		tortoise = func(tortoise);
		hare = func(func(hare));

		if (tortoise == hare)
		{
			tortoise = start;
			while (tortoise != hare)
			{
				tortoise = func(tortoise);
				hare = func(hare);
			}
			return tortoise;
		}
	}
}

data_t detectLargestTreeRoot(func_t func)
{
#define SAMPLE 100
	ofstream fout;
	fn = "n" + to_string(n) + "_attack_record.txt";

	map<data_t, u64> alphaNodes;
	map<data_t, u64>::iterator it;
	data_t alphaNode;

	for (u64 i = 0; i < SAMPLE; i++)
	{
		alphaNode = cycleSearch(func);
		it = alphaNodes.find(alphaNode);
		if (it != alphaNodes.end())
		{
			it->second++;
		}
		else
		{
			alphaNodes.insert(pair<data_t, u64>(alphaNode, 1UL));
		}
	}

	data_t root;
	u64 maxFreq = 0UL;

	for (it = alphaNodes.begin(); it != alphaNodes.end(); ++it)
	{
		if (it->second > maxFreq)
		{
			root = it->first;
			maxFreq = it->second;
		}
	}
	fout.open(fn.c_str(), ios::app);
	cout << "Frequency: " << (double)maxFreq / (double)SAMPLE << endl;
	fout << "Frequency: " << (double)maxFreq / (double)SAMPLE << endl;
	fout.close();
	return root;
}

void preCompute(unordered_map<data_t, u64> &G, func_t func, data_t target)
{
	unordered_map<data_t, u64>::iterator GIt;
	list<pair<data_t, u64>> chain;
	list<pair<data_t, u64>>::iterator chainIt;
	unordered_map<data_t, u64> chainInd;
	unordered_map<data_t, u64>::iterator chainIndIt;

	data_t x;
	data_t y;
	u64 distance;
	while (G.size() < T)
	{
		chain.clear();
		chainInd.clear();

		while (0 == _rdseed32_step(&y)) {}
		y &= mask;
		if (y == target)
		{
			chain.push_front(pair<data_t, u64>(y, 0ULL));
			chainInd.insert(pair<data_t, u64>(y, 0ULL));
		}
		else
		{
			chain.push_front(pair<data_t, u64>(y, INF));
			chainInd.insert(pair<data_t, u64>(y, INF));
		}

		while (true)
		{
			GIt = G.find(y);		
			if (GIt != G.end())
			{// y is already exist in G
				if (GIt->second != INF)
				{// target is reachable from y
					distance = GIt->second + 1ULL;
					chain.pop_front();
					while (!chain.empty())
					{
						data_t z = chain.front().first;
						G.insert(pair<data_t, u64>(z, distance));
						chain.pop_front();
						chainInd.erase(z);
						distance++;
					}
				}
				else
				{// target is not reachable from y
					chain.pop_front();
					while (!chain.empty())
					{
						data_t z = chain.front().first;
						G.insert(chain.front());
						chain.pop_front();
						chainInd.erase(z);
					}
				}
				break;
			}
			else
			{
				data_t x = func(y);
				chainIndIt = chainInd.find(x);
				if (chainIndIt != chainInd.end())
				{// image of y is already exist in chain, and not exist in G
					distance = chainIndIt->second;
					if (distance != INF)
					{// update distance to target if target is in circle of this current chain
						distance++;
						chainIt = chain.begin();
						data_t z = chainIt->first;
						while (z != target)
						{
							chainIt->second = distance;
							chainInd[z] = distance;
							chainIt++;
							z = chainIt->first;
							distance++;
						}
					}
					while (!chain.empty())
					{
						pair<data_t, u64> tmp = chain.front();
						data_t z = tmp.first;
						G.insert(tmp);
						chain.pop_front();
						chainInd.erase(z);
					}
					break;
				}
				else //(chainIndIt == chainInd.end())
				{ // image of y is not exist in chain
					y = x;
					if (y == target)
					{ // update distance to target of those node in these current chain if encounter the target
						chain.push_front(pair<data_t, u64>(y, 0ULL));
						chainInd.insert(pair<data_t, u64>(y, 0ULL));
						distance = 0UL;
						for (chainIt = chain.begin(); chainIt != chain.end(); ++chainIt)
						{
							chainIt->second = distance;
							chainInd[chainIt->first] = distance;
							distance++;
						}
					}
					else
					{
						chain.push_front(pair<data_t, u64>(y, INF));
						chainInd.insert(pair<data_t, u64>(y, INF));
					}
				}
			}
		}
	}
}

data_t collision(u8 mblock1[16], u8 mblock2[16], comp_t comp, data_t start)
{
	unordered_map<data_t, mb_t> evaluated;
	unordered_map<data_t, mb_t>::iterator evaluatedIt;
	mb_t mblockt;
	((u64 *)mblockt.block)[0] = 0ULL;
	((u64 *)mblockt.block)[1] = 0ULL;
	u64 i = 0ULL;
	data_t endtmp;
	do
	{
		//randmblock(mblockt);
		((u64 *)mblockt.block)[0] = i;
		endtmp = comp(start, mblockt.block);
		i++;
		evaluatedIt = evaluated.find(endtmp);
		if (evaluatedIt == evaluated.end())
		{
			evaluated.insert(pair<data_t, mb_t>(endtmp, mblockt));
		}
		else
		{
			memcpy(mblock2, evaluatedIt->second.block, BLOCK_SIZE);
			//if (memcmp(mblockt, mblock2, BLOCK_SIZE) != 0)
			{
				memcpy(mblock1, mblockt.block, BLOCK_SIZE);
				evaluated.clear();
				return endtmp;
			}
		}
	} while (true);
}

data_t collision(u8 mblock1[16], u8 mblock2[16], comp_t comp, data_t start1, data_t start2)
{
	unordered_map<data_t, mb_t> evaluated1;
	unordered_map<data_t, mb_t>::iterator evaluatedIt1;

	unordered_map<data_t, mb_t> evaluated2;
	unordered_map<data_t, mb_t>::iterator evaluatedIt2;

	mb_t mblockt1;
	mb_t mblockt2;
	((u64 *)mblockt1.block)[0] = 0ULL;
	((u64 *)mblockt1.block)[1] = 0ULL;

	((u64 *)mblockt2.block)[0] = 0ULL;
	((u64 *)mblockt2.block)[1] = 0ULL;

	data_t endtmp1;
	data_t endtmp2;

	u64 i1 = 0ULL;
	u64 i2 = 0ULL;

	do
	{
		((u64 *)mblockt1.block)[0] = i1;
		endtmp1 = comp(start1, mblockt1.block);
		i1++;

		evaluatedIt2 = evaluated2.find(endtmp1);
		if (evaluatedIt2 == evaluated2.end())
		{
			evaluated1.insert(pair<data_t, mb_t>(endtmp1, mblockt1));
			((u64 *)mblockt2.block)[0] = i2;
			endtmp2 = comp(start2, mblockt2.block);
			i2++;

			evaluatedIt1 = evaluated1.find(endtmp2);
			if (evaluatedIt1 == evaluated1.end())
			{
				evaluated2.insert(pair<data_t, mb_t>(endtmp2, mblockt2));
				continue;
			}
			else
			{
				memcpy(mblock1, evaluatedIt1->second.block, BLOCK_SIZE);
				memcpy(mblock2, mblockt2.block, BLOCK_SIZE);
				evaluated1.clear();
				evaluated2.clear();
				return endtmp2;
			}
		}
		else
		{
			memcpy(mblock1, mblockt1.block, BLOCK_SIZE);
			memcpy(mblock2, evaluatedIt2->second.block, BLOCK_SIZE);
			evaluated1.clear();
			evaluated2.clear();

			return endtmp1;
		}
	} while (true);
}

data_t multiCollision(vector<mb_t> * M1, vector<mb_t> * M2, comp_t comp, data_t start, u64 k)
{
	mb_t mblock1;
	mb_t mblock2;
	data_t end = start;
	for (u64 i = 0ULL; i < k; i++)
	{
		end = collision(mblock1.block, mblock2.block, comp, end);
		M1->push_back(mblock1);
		M2->push_back(mblock2);
	}
	return end;
}

data_t simExpandMBlock_pass1(vector<mb_t> * M1, vector<mb_t> * M2, comp_t comp, func_t func, data_t start, u64 i)
{
	data_t xa = multiCollision(M1, M2, comp, start, C - 1);
	data_t xp = xa;
	mb_t mblock1;
	mb_t mblock2;

	u64 subl = i - C;
	for (u64 j = 0; j < subl; j++)
	{
		xp = func(xp);
	}

	xp = collision(mblock1.block, mblock2.block, comp, xa, xp);
	M1->push_back(mblock1);
	M2->push_back(mblock2);

	return xp;
}

data_t simExpandM_pass1(comp_t comp, func_t func, data_t start)
{
	data_t end = start;
	vector<mb_t> M1;
	vector<mb_t> M2;
	for (u64 j = 0ULL; j < C - 1ULL; j++)
	{
		M1.clear();
		M2.clear();
		end = simExpandMBlock_pass1(&M1, &M2, comp, func, end, C + 1 + j);
		M1S.push_back(M1);
		M1L.push_back(M2);
	}
	for (u64 j = 0ULL; j < et; j++)
	{
		M1.clear();
		M2.clear();
		end = simExpandMBlock_pass1(&M1, &M2, comp, func, end, C * ((1ULL << j) + 1ULL));
		M1S.push_back(M1);
		M1L.push_back(M2);
	}
	M1.clear();
	M2.clear();

	return end;
}

bool simExpandM_pass2(data_t* end,  comp_t comp, func_t func, data_t start)
{
	data_t end1;
	data_t end2;

	vector<mb_t> * M1It;
	vector<mb_t> * M2It;

	mb_t * MB1It;
	mb_t * MB2It;

	unordered_map<data_t, vector<mb_t>> ends1;
	unordered_map<data_t, vector<mb_t>> ends2;

	unordered_map<data_t, vector<mb_t>>::iterator ends1It;
	unordered_map<data_t, vector<mb_t>>::iterator ends2It;

	vector<mb_t> MStmp;
	vector<mb_t> MLtmp;

	vector<mb_t> MSJouxtmp;
	vector<mb_t> MLJouxtmp;
	
	data_t endTmp1;	
	data_t endTmp2;

	*end = start;

	for (u64 esi = 0; esi <= ES; esi++)
	{	
		u64 zeron = (esi < et) ? ((1ULL << (et - 1 - esi))) * C : (C - 1 - (esi - et));

		end1 = end2 = *end;
		M1It = &M1S.back();
		M2It = &M1L.back();

		MB1It = &(M1It->back());
		end1 = comp(end1, MB1It->block);
		MStmp.push_back(*MB1It);
		MSJouxtmp.push_back(*MB1It);
		M1It->pop_back();

		MB2It = &(M2It->back());
		end2 = comp(end2, MB2It->block);
		MLtmp.push_back(*MB2It);
		MLJouxtmp.push_back(*MB2It);
		M2It->pop_back();

		for (u64 zi = 0; zi < zeron; zi++)
		{
			end2 = func(end2);
		}

		u64 ind = 0ULL;
		u64 j;
		for (j = 0ULL; j < (1ULL << (C - 1ULL)); j++)
		{
			endTmp1 = end1;
			endTmp2 = end2;

			for (u64 b = 0ULL; b < C - 1ULL; b++)
			{
				u64 cb = C - 2ULL - b;
				ind = (j >> cb) & 1ULL;
				u8 *mblockt;
				if (ind == 0)
				{
					MB1It = &((*M1It)[cb]);
					mblockt = MB1It->block;
					MSJouxtmp.push_back(*MB1It);
					MLJouxtmp.push_back(*MB1It);
				}
				else
				{
					MB2It = &((*M2It)[cb]);
					mblockt = MB2It->block;
					MSJouxtmp.push_back(*MB2It);
					MLJouxtmp.push_back(*MB2It);
				}
				endTmp1 = comp(endTmp1, mblockt);
				endTmp2 = comp(endTmp2, mblockt);
			}
			ends1.insert(pair<data_t, vector<mb_t>>(endTmp1, MSJouxtmp));
			ends2.insert(pair<data_t, vector<mb_t>>(endTmp2, MLJouxtmp));

			ends1It = ends1.find(endTmp2);
			if (ends1It != ends1.end())
			{
				MS.push_back(ends1It->second);
				ML.push_back(MLJouxtmp);
				*end = endTmp2;
				for (u64 b = 0ULL; b < C - 1ULL; b++)
				{
					MSJouxtmp.pop_back();
					MLJouxtmp.pop_back();
				}
				break;
			}
			else
			{
				ends2It = ends2.find(endTmp1);
				if (ends2It != ends2.end())
				{
					MS.push_back(MSJouxtmp);
					ML.push_back(ends2It->second);
					*end = endTmp1;
					for (u64 b = 0ULL; b < C - 1ULL; b++)
					{
						MSJouxtmp.pop_back();
						MLJouxtmp.pop_back();
					}
					break;
				}
			}
			for (u64 b = 0ULL; b < C - 1ULL; b++)
			{
				MSJouxtmp.pop_back();
				MLJouxtmp.pop_back();
			}
		}
		if (j == (1ULL << (C - 1ULL)))
		{
			MStmp.clear();
			MLtmp.clear();
			MSJouxtmp.clear();
			MLJouxtmp.clear();
			ends1.clear();
			ends2.clear();
			M1S.clear();
			M1L.clear();
			return false;
		}
		MStmp.clear();
		MLtmp.clear();
		MSJouxtmp.clear();
		MLJouxtmp.clear();
		ends1.clear();
		ends2.clear();

		M1S.pop_back();
		M1L.pop_back();
	}
	return true;
}

data_t simExpandM(data_t start)
{
	data_t xa;
	data_t xb;
	u8 lastBlock[16];
	((u64 *)lastBlock)[0] = Lp;
	((u64 *)lastBlock)[1] = 0ULL;
	bool suc = false;
	do
	{
		xa = simExpandM_pass1(h1, f1, start);
		xb = h2(h1(xa, lastBlock), lastBlock);
		suc = simExpandM_pass2(&xb, h2, f2, xb);
		ofstream fout;
		fn = "n" + to_string(n) + "_attack_record.txt";
		fout.open(fn.c_str(), ios::app);
		cout << "simExpandM: " << (suc ? "success" : "failure") << endl;
		fout << "simExpandM: " << (suc ? "success" : "failure") << endl;
		fout.close();
	} while (suc == false);
	return xb;
}

bool hitSecondPass(u64 * q, mb_t * m_bar, data_t start, comp_t comp)
{
	unordered_multimap<data_t, u64> chainStates;
	unordered_multimap<data_t, u64>::iterator chainStatesIt;
	u8 mblockt[16];
	data_t yqTmp;
	for (u64 i = 0; i < L; i++)
	{
		chainStates.insert(pair<data_t, u64>(OMS[L + 1 + i], L - i));
	}
	u64 i = 0ULL;
	((u64 *)mblockt)[1] = 0;
	do
	{
		((u64 *)mblockt)[0] = i;
		yqTmp = comp(start, mblockt);
		chainStatesIt = chainStates.find(yqTmp);
		i++;
	} while (chainStatesIt == chainStates.end());

	*q = chainStatesIt->second;
	memcpy(m_bar->block, mblockt, BLOCK_SIZE);
	return true;
}

void openJouxMC2_pass1(data_t start, comp_t comp, func_t func)
{
	vector<mb_t>::iterator MJoux2It;
	vector<mb_t> MJoux2tmp;
	data_t endTmp = start;
	u64 ind = 0ULL;

	for (u64 i = 0ULL; i < R; i++)
	{
		for (u64 j = 0ULL; j < r; j++)
		{
			ind = (i >> j) & 1ULL;
			u8 *mblockt;
			if (ind == 0)
			{
				mblockt = MJoux2[0][r - 1 - j].block;
				MJoux2tmp.push_back(MJoux2[0][r - 1 - j]);
			}
			else
			{
				mblockt = MJoux2[1][r - 1 - j].block;
				MJoux2tmp.push_back(MJoux2[1][r - 1 - j]);
			}
			endTmp = comp(endTmp, mblockt);
		}
		unordered_map<data_t, u64>::iterator G1It;
		u64 depth = 0ULL;
		do
		{
			G1It = G1.find(endTmp);
			if ((G1It == G1.end()) && (depth < W))
			{
				endTmp = func(endTmp);
				depth++;
			}
			else if (G1It != G1.end())
			{
				u64 d1 = G1It->second;
				if (d1 != INF)
				{
					DT1.insert(pair<u64, vector<mb_t>>(d1 + depth, MJoux2tmp));
				}
				break;
			}
			else
			{
				break;
			}
		} while (true);
		endTmp = start;
		MJoux2tmp.clear();
	}
}

bool getSimExpandM(u64 k)
{
	if ((k < EL) || (k > EU))
	{
		ofstream fout;
		fn = "n" + to_string(n) + "_attack_record.txt";
		fout.open(fn.c_str(), ios::app);
		cout << "Length out of range of Simultaneous Expandable Message." << endl;
		fout << "Length out of range of Simultaneous Expandable Message." << endl;
		fout.close();
		return false;
	}

	u64 kp;
	for (kp = C * (C - 1); kp <= (C * C - 1); kp++)
	{
		if ((kp % C) == (k % C)) break;
	}
	u64 longFragment = kp - C * (C - 1);
	if (longFragment == 0)
	{
		for (u64 i = 0; i < C - 1; i++)
		{
			for (u64 j = 0; j < C; j++)
			{
				Me.push_back(MS[ES - i][C - 1 - j]);
			}
		}
	}
	else
	{
		for (u64 i = 0; i < longFragment - 1; i++)
		{
			for (u64 j = 0; j < C; j++)
			{
				Me.push_back(MS[ES - i][C - 1 - j]);
			}
		}

		for (u64 j = 0; j < C - 1; j++)
		{
			Me.push_back(ML[ES - (longFragment - 1)][C - 1 - j]);
		}

		for (u64 j = 0; j < longFragment; j++)
		{
			mb_t zerom;
			zeromblock(zerom.block);
			Me.push_back(zerom);
		}

		Me.push_back(ML[ES - (longFragment - 1)][0]);

		for (u64 i = longFragment; i < C - 1; i++)
		{
			for (u64 j = 0; j < C; j++)
			{
				Me.push_back(MS[ES - i][C - 1 - j]);
			}
		}
	}
	k -= kp;

	if (k < (et * C))
	{
		ofstream fout;
		fn = "n" + to_string(n) + "_attack_record.txt";
		fout.open(fn.c_str(), ios::app);
		cout << "Length invalid for Simultaneous Expandable Message." << endl;
		fout << "Length invalid for Simultaneous Expandable Message." << endl;
		fout.close();
		return false;
	}
	else
	{
		u64 tp;
		tp = k / C;

		tp = tp - et;

		u64 Ind;
		for (u64 i = 0ULL; i < et; i++)
		{
			Ind = (tp >> i) & 0x1ULL;
			if (Ind == 0)
			{
				for (u64 j = 0; j < C; j++)
				{
					Me.push_back(MS[ES - (C - 1 + i)][C - 1 - j]);
				}
			}
			else
			{
				for (u64 j = 0; j < C - 1; j++)
				{
					Me.push_back(ML[ES - (C - 1 + i)][C - 1 - j]);
				}

				for (u64 j = 0; j < C * ((1UL << i)); j++)
				{
					mb_t zerom;
					zeromblock(zerom.block);
					Me.push_back(zerom);
				}
				Me.push_back(ML[ES - (C - 1 + i)][0]);
			}
		}
	}
	return true;
}

bool openJouxMC1_pass2(data_t start, comp_t comp, func_t func)
{
	vector<mb_t>::iterator MJoux1It;
	vector<mb_t> MJoux1tmp;
	data_t endTmp = start;
	u64 ind = 0ULL;

	for (u64 i = 0ULL; i < R; i++)
	{
		for (u64 j = 0ULL; j < r; j++)
		{
			ind = (i >> j) & 1ULL;
			u8 *mblockt;
			if (ind == 0)
			{
				mblockt = MJoux1[0][r - 1 - j].block;
				MJoux1tmp.push_back(MJoux1[0][r - 1 - j]);
			}
			else
			{
				mblockt = MJoux1[1][r - 1 - j].block;
				MJoux1tmp.push_back(MJoux1[1][r - 1 - j]);
			}
			endTmp = comp(endTmp, mblockt);
		}
		unordered_map<data_t, u64>::iterator G2It;
		unordered_map<u64, vector<mb_t>>::iterator DT1It;
		u64 depth = 0ULL;
		do
		{
			G2It = G2.find(endTmp);
			if ((G2It == G2.end()) && (depth < W))
			{
				endTmp = func(endTmp);
				depth++;
			}
			else if (G2It != G2.end())
			{
				d2 = G2It->second;
				if ((d2 != INF) && ((d2 + depth + EL) <= (Lp - q - 1 - r - r) ) && ((d2 + depth + EU) >= (Lp - q - 1 - r - r)))
				{
					d2 += depth;
					DT1It = DT1.find(d2);
					if (DT1It != DT1.end())
					{
						dr = Lp - q - 1 - r - d2 - r;
						if (getSimExpandM(dr))
						{
							u64 mi = 0ULL;
							for (u64 oi = 0ULL; oi < q; oi++)
							{
								SM[mi++] = OM[oi];
							}
							SM[mi++] = m_bar;
							for (u64  oi = 0ULL; oi < r; oi++)
							{
								SM[mi++] = DT1It->second[oi];
							}
							for (u64  oi = 0ULL; oi < d2; oi++)
							{
								memcpy(SM[mi++].block, m, BLOCK_SIZE);
							}
							for (u64 oi = 0ULL; oi < r; oi++)
							{
								SM[mi++] = MJoux1tmp[r - 1 - oi];
							}
							for (u64 oi = 0ULL; oi < dr; oi++)
							{
								SM[mi++] = Me[oi];
							}
							((u64 *)(SM[Lp].block))[0] = Lp;
							((u64 *)(SM[Lp].block))[1] = 0x0ULL;
							MJoux1tmp.clear();
							return true;
						}
						break;
					}
				}
				break;
			}
			else
			{
				break;
			}
		} while (true);
		endTmp = start;
		MJoux1tmp.clear();
	}
	return false;
}

void attack()
{
	ofstream fout;

#define TRAILS 10
	u64 sucR = 0ULL;
	bool suc;

	for (n = nMin; n <= nMax; n+= 8)
	{
		sucR = 0ULL;
		fn = "n" + to_string(n) + "_attack_record.txt";
		fout.open(fn.c_str(), ios::app);
		fout << "===============================================================================================" << endl;
		fout << " n = " << n << endl;
		fout << "===============================================================================================" << endl;
		cout << "===============================================================================================" << endl;
		cout << " n = " << n << endl;
		cout << "===============================================================================================" << endl;
		fout.close();

		for (u64 si = 0ULL; si < TRAILS; si++)
		{
			cout << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   Attack " << si << " start..." << endl;
			fn = "n" + to_string(n) + "_attack_record.txt";
			fout.open(fn.c_str(), ios::app);
			fout << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   Attack " << si << " start..." << endl;
			fout.close();

			OM = new mb_t[L + 1];
			OMS = new data_t[(L + 1) * 2];

			SM = new mb_t[Lp + 1];
			SMS = new data_t[(Lp + 1) * 2];

			for (u64 i = 0; i < L; i++)
			{
				randmblock(OM[i].block);
			}
			((u64 *)(OM[L].block))[0] = L;
			((u64 *)(OM[L].block))[1] = 0ULL;

			data_t hash1 = Zipper(OM, OMS, L);

			zeromblock(m);
			init_func();

			clock_t t0 = clock();
			functionCall = 0ULL;
			data_t x_bar = detectLargestTreeRoot(f1);
			data_t y_bar = detectLargestTreeRoot(f2);
			t0 = clock() - t0;
			fout.open(fn.c_str(), ios::app);
			cout << std::resetiosflags(std::ios::adjustfield);
			cout << std::setiosflags(std::ios::left);
			fout << std::resetiosflags(std::ios::adjustfield);
			fout << std::setiosflags(std::ios::left);
			cout << std::setfill ('-') << setw(90) << "Detect Largest Tree Root # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			fout << std::setfill ('-') << setw(90) << "Detect Largest Tree Root # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			cout << std::setfill ('-') << setw(90) << "Detect Largest Tree Root Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			fout << std::setfill ('-') << setw(90) << "Detect Largest Tree Root Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			cout << endl;
			fout << endl;
			fout.close();

			t0 = clock();
			functionCall = 0ULL;
			preCompute(G1, f1, x_bar);
			preCompute(G2, f2, y_bar);
			t0 = clock() - t0;
			fout.open(fn.c_str(), ios::app);
			fout << std::resetiosflags(std::ios::adjustfield);
			fout << std::setiosflags(std::ios::left);
			cout << std::setfill ('-') << setw(90) << "Precomputation # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			fout << std::setfill ('-') << setw(90) << "Precomputation # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			cout << std::setfill ('-') << setw(90) << "Precomputation Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			fout << std::setfill ('-') << setw(90) << "Precomputation Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			cout << endl;
			fout << endl;
			fout.close();

			t0 = clock();
			functionCall = 0ULL;
			data_t x_hat = multiCollision(&MJoux1[0], &MJoux1[1], h1, x_bar, r);
			data_t y_hat = multiCollision(&MJoux2[0], &MJoux2[1], h2, y_bar, r);
			t0 = clock() - t0;
			fout.open(fn.c_str(), ios::app);
			fout << std::resetiosflags(std::ios::adjustfield);
			fout << std::setiosflags(std::ios::left);
			cout << std::setfill ('-') << setw(90) << "Joux's multiCollision # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			fout << std::setfill ('-') << setw(90) << "Joux's multiCollision # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			cout << std::setfill ('-') << setw(90) << "Joux's multiCollision Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			fout << std::setfill ('-') << setw(90) << "Joux's multiCollision Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			cout << endl;
			fout << endl;
			fout.close();

			t0 = clock();
			functionCall = 0ULL;
			data_t y_tilde = simExpandM(x_hat);
			t0 = clock() - t0;
			fout.open(fn.c_str(), ios::app);
			fout << std::resetiosflags(std::ios::adjustfield);
			fout << std::setiosflags(std::ios::left);
			cout << std::setfill ('-') << setw(90) << "Simultaneous Expandable Massage # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			fout << std::setfill ('-') << setw(90) << "Simultaneous Expandable Massage # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			cout << std::setfill ('-') << setw(90) << "Simultaneous Expandable Massage Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			fout << std::setfill ('-') << setw(90) << "Simultaneous Expandable Massage Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			cout << endl;
			fout << endl;
			fout.close();

			t0 = clock();
			functionCall = 0ULL;
			suc = hitSecondPass(&q, &m_bar, y_hat, h2);
			t0 = clock() - t0;
			fout.open(fn.c_str(), ios::app);
			fout << std::resetiosflags(std::ios::adjustfield);
			fout << std::setiosflags(std::ios::left);
			cout << std::setfill ('-') << setw(90) << "Hitting state in the second pass " << ((suc) ? "Success." : "Failure.") << endl;
			fout << std::setfill ('-') << setw(90) << "Hitting state in the second pass " << ((suc) ? "Success." : "Failure.") << endl;
			cout << std::setfill ('-') << setw(90) << "Hitting state in the second passHitting state in the second pass # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			fout << std::setfill ('-') << setw(90) << "Hitting state in the second passHitting state in the second pass # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			cout << std::setfill ('-') << setw(90) << "Hitting state in the second pass Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			fout << std::setfill ('-') << setw(90) << "Hitting state in the second pass Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			cout << endl;
			fout << endl;
			fout.close();

			data_t x_tilde = h1(OMS[q - 1], m_bar.block);

			t0 = clock();
			functionCall = 0ULL;
			openJouxMC2_pass1(x_tilde, h1, f1);
			suc = openJouxMC1_pass2(y_tilde, h2, f2);
			t0 = clock() - t0;
			fout.open(fn.c_str(), ios::app);
			fout << std::resetiosflags(std::ios::adjustfield);
			fout << std::setiosflags(std::ios::left);
			cout << std::setfill ('-') << setw(90) << "Hitting two roots Simultaneously " << ((suc) ? "Success." : "Failure.") << endl;
			fout << std::setfill ('-') << setw(90) << "Hitting two roots Simultaneously " << ((suc) ? "Success." : "Failure.") << endl;
			cout << std::setfill ('-') << setw(90) << "Hitting two roots Simultaneously # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			fout << std::setfill ('-') << setw(90) << "Hitting two roots Simultaneously # Function Calls: 2^" << logl((ld64)(functionCall)) / logl(2.0L) << endl;
			cout << std::setfill ('-') << setw(90) << "Hitting two roots Simultaneously Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			fout << std::setfill ('-') << setw(90) << "Hitting two roots Simultaneously Takes time: " << (double)(t0) / ((double)CLOCKS_PER_SEC * 60.0) << " mins." << endl;
			cout << endl;
			fout << endl;
			fout.close();

			data_t hash2 = Zipper(SM, SMS, Lp);
			suc = (hash2 == hash1);
			sucR += (suc ? 1ULL : 0ULL);
			fout.open(fn.c_str(), ios::app);
			cout << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   Attack " << si << " end with " << (suc ? "Success." : "Failure.") << endl;
			fout << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   Attack " << si << " end with " << (suc ? "Success." : "Failure.") << endl;
			cout << endl;
			fout << endl;
			fout.close();

			end_func();

			G1.clear();
			G2.clear();
			M1S.clear();
			M1L.clear();
			MS.clear();
			ML.clear();
			MJoux1[0].clear();
			MJoux1[1].clear();
			MJoux2[0].clear();
			MJoux2[1].clear();
			Me.clear();
			DT1.clear();
			delete[] OM;
			delete[] OMS;
			delete[] SM;
			delete[] SMS;
		}
		fout.open(fn.c_str(), ios::app);
		cout << "Attack success ratio: " << (double)sucR/(double)TRAILS << endl;
		fout << "Attack success ratio: " << (double)sucR/(double)TRAILS << endl;
		cout << endl;
		fout << endl;
		fout.close();
	}
}


int main()
{
	/* Init Intel IPP library */
	ippInit();

	attack();
#if defined(_MSC_VER)
	system("Pause");
#endif
	return 0;
}

