#define NUM_ZERO 0
#define NUM_ONE 1
#define NUM_TWO 2
#define NUM_THREE 3
#define NUM_FOUR 4
#define NUM_FIVE 5
#define NUM_SIX 6

#define GET_COMM_ARGS \
GlobalTensor<int> commArgsGm; \
commArgsGm.SetGlobalBuffer(reinterpret_cast<__gm__ int *>(commArgs), NUM_SIX); \
int rank = commArgsGm.GetValue(NUM_ZERO); \
int localRank = commArgsGm.GetValue(NUM_ONE); \
int rankSize = commArgsGm.GetValue(NUM_TWO); \
int localRankSize = commArgsGm.GetValue(NUM_THREE); \
uint32_t extraFlag = commArgsGm.GetValue(NUM_FOUR); \
int testFlag = commArgsGm.GetValue(NUM_FIVE)