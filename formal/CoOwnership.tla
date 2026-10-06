----------------------------- MODULE CoOwnership -----------------------------
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS Owners, Modes, Alice, Bob, Carol, RootMain, RootFork,
          A, B, C, D, R, S, T, U, F, MainScope, ForkScope, Mutation

ASSUME /\ Owners = {Alice, Bob, Carol}
       /\ Modes = {"Majority", "Unanimous"}
       /\ Alice \in Owners /\ Bob \in Owners /\ Carol \in Owners
       /\ MainScope # ForkScope
       /\ Mutation \in {"None", "Threshold", "StaleReplay", "ForgetConflict",
                        "RecoveryBypass", "Liveness"}

VARIABLES heads, headProof, nodes, forkExists, recoveredIdentity,
          issued, observed, children, selected, covered, open, resolveSigs

vars == <<heads, headProof, nodes, forkExists, recoveredIdentity,
          issued, observed, children, selected, covered, open, resolveSigs>>

Node(epoch, owners, identity, mode, parent, scope) ==
  <<epoch, owners, identity, mode, parent, scope>>

Epoch(n) == nodes[n][1]
NodeOwners(n) == nodes[n][2]
NodeIdentity(n) == nodes[n][3]
NodeMode(n) == nodes[n][4]
NodeParent(n) == nodes[n][5]
NodeScope(n) == nodes[n][6]

CandidateCerts == {
  [id |-> "branch-A", scope |-> MainScope, parent |-> RootMain,
   epoch |-> 3, child |-> A, kind |-> "Composition", signers |-> {Alice, Bob},
   owners |-> {Alice, Bob, Carol}, identity |-> Alice, mode |-> "Majority", refs |-> {}],
  [id |-> "branch-B", scope |-> MainScope, parent |-> RootMain,
   epoch |-> 3, child |-> B, kind |-> "Composition", signers |-> {Alice, Bob},
   owners |-> {Bob}, identity |-> Bob, mode |-> "Majority", refs |-> {}],
  [id |-> "late-branch-C", scope |-> MainScope, parent |-> RootMain,
   epoch |-> 3, child |-> C, kind |-> "Policy", signers |-> {Alice, Bob},
   owners |-> {Alice, Bob}, identity |-> Alice, mode |-> "Unanimous", refs |-> {}],
  [id |-> "descendant-D", scope |-> MainScope, parent |-> A,
   epoch |-> 4, child |-> D, kind |-> "Policy", signers |-> {Alice, Bob},
   owners |-> {Alice, Bob, Carol}, identity |-> Alice, mode |-> "Unanimous", refs |-> {}],
  [id |-> "resolve-R", scope |-> MainScope, parent |-> RootMain,
   epoch |-> 3, child |-> R, kind |-> "Resolution", signers |-> {Alice, Bob},
   owners |-> {Alice, Bob}, identity |-> Alice, mode |-> "Majority", refs |-> {A, B}],
  [id |-> "resolve-S-stale", scope |-> MainScope, parent |-> RootMain,
   epoch |-> 3, child |-> S, kind |-> "Resolution", signers |-> {Alice, Bob},
   owners |-> {Bob}, identity |-> Bob, mode |-> "Majority", refs |-> {A, B}],
  [id |-> "resolve-T-covering", scope |-> MainScope, parent |-> RootMain,
   epoch |-> 3, child |-> T, kind |-> "Resolution", signers |-> {Alice, Bob},
   owners |-> {Alice, Bob}, identity |-> Alice, mode |-> "Unanimous", refs |-> {A, B, R, S}],
  [id |-> "resolve-U-late", scope |-> MainScope, parent |-> RootMain,
   epoch |-> 3, child |-> U, kind |-> "Resolution", signers |-> {Alice, Bob},
   owners |-> {Alice, Bob}, identity |-> Alice, mode |-> "Majority", refs |-> {A, B, R, S, T, C}],
  [id |-> "fork-branch-F", scope |-> ForkScope, parent |-> RootFork,
   epoch |-> 1, child |-> F, kind |-> "Policy", signers |-> {Carol},
   owners |-> {Carol}, identity |-> Carol, mode |-> "Unanimous", refs |-> {}],
  [id |-> "bad-one-signature", scope |-> MainScope, parent |-> RootMain,
   epoch |-> 3, child |-> U, kind |-> "Composition", signers |-> {Alice},
   owners |-> {Alice}, identity |-> Alice, mode |-> "Majority", refs |-> {}]
}

CertById(id) == CHOOSE c \in CandidateCerts : c.id = id

AllNodes == {RootMain, RootFork, A, B, C, D, R, S, T, U, F}
Scopes == {MainScope, ForkScope}
Roots == {RootMain, RootFork}
NodeIds == AllNodes
NodeRecords == (-1..10) \X (SUBSET Owners) \X Owners \X Modes
               \X ({""} \cup AllNodes) \X Scopes
HeadProofs == (0..10) \X AllNodes
Threshold(n, m) == IF m = "Unanimous" THEN n ELSE (n \div 2) + 1
HasQuorum(signers, electorate, m) ==
  /\ signers \subseteq electorate
  /\ Cardinality(signers) >= Threshold(Cardinality(electorate), m)

RECURSIVE Ancestors(_)
Ancestors(n) ==
  IF n \in Roots \/ Epoch(n) <= 0 THEN {n}
  ELSE {n} \cup Ancestors(NodeParent(n))

ScopeOpen(scope) == \E p \in AllNodes : open[p] /\ p \in Ancestors(heads[scope])
CanAuthorize(scope) == ~ScopeOpen(scope)
CertParentValid(c) ==
  /\ c.parent \in AllNodes
  /\ NodeScope(c.parent) = c.scope
  /\ c.epoch = Epoch(c.parent) + 1
  /\ HasQuorum(c.signers, NodeOwners(c.parent), NodeMode(c.parent))
  /\ c.owners \subseteq Owners
  /\ c.owners # {}
  /\ c.mode \in Modes
  /\ IF c.kind = "Recovery"
       THEN c.identity = NodeIdentity(c.parent)
       ELSE c.identity \in Owners

ResolutionProposalValid(c) ==
  /\ c.kind = "Resolution"
  /\ c.parent \in AllNodes
  /\ open[c.parent]
  /\ c.refs = children[c.parent]

NormalProposalValid(c) ==
  /\ c.kind \in {"Composition", "Policy", "Recovery"}
  /\ c.parent = heads[c.scope]
  /\ CanAuthorize(c.scope)
  /\ IF c.kind = "Composition"
       THEN c.mode = NodeMode(c.parent)
       ELSE IF c.kind = "Policy"
              THEN c.owners = NodeOwners(c.parent)
                   /\ c.identity = NodeIdentity(c.parent)
              ELSE /\ c.owners = NodeOwners(c.parent)
                   /\ c.mode = NodeMode(c.parent)
                   /\ c.identity = NodeIdentity(c.parent)

ValidProposal(c) ==
  /\ CertParentValid(c)
  /\ c.child \in AllNodes
  /\ Epoch(c.child) = -1
  /\ (NormalProposalValid(c) \/ ResolutionProposalValid(c))

Init ==
  /\ heads = [s \in Scopes |-> IF s = MainScope THEN RootMain ELSE RootFork]
  /\ headProof = [s \in Scopes |-> <<0, heads[s]>>]
  /\ forkExists = FALSE
  /\ recoveredIdentity = ""
  /\ nodes = [n \in AllNodes |->
       IF n = RootMain THEN Node(2, {Alice, Bob}, Alice, "Majority", "", MainScope)
       ELSE IF n = RootFork THEN Node(-1, {}, Carol, "Majority", "", ForkScope)
       ELSE Node(-1, {}, Alice, "Majority", "", MainScope)]
  /\ issued = {}
  /\ observed = {}
  /\ children = [n \in AllNodes |-> {}]
  /\ selected = [n \in AllNodes |-> ""]
  /\ covered = [n \in AllNodes |-> {}]
  /\ open = [n \in AllNodes |-> FALSE]
  /\ resolveSigs = [n \in AllNodes |-> {}]

Issue(c) ==
  /\ c \in CandidateCerts
  /\ (Mutation # "Liveness" \/ c.id \in {"branch-A", "branch-B", "resolve-R"})
  /\ ValidProposal(c)
  /\ c.id \notin issued
  /\ ~\E id \in issued : CertById(id).child = c.child
  /\ issued' = issued \cup {c.id}
  /\ UNCHANGED <<heads, headProof, nodes, forkExists, recoveredIdentity, observed, children,
                  selected, covered, open, resolveSigs>>

Observe(c) ==
  /\ c.kind # "Resolution"
  /\ c.id \in issued
  /\ c.id \notin observed
  /\ Epoch(c.child) = -1
  /\ LET newChildren == children[c.parent] \cup {c.child}
         resolves == FALSE
         conflictAfter == Cardinality(newChildren) >= 2
            /\ ~(newChildren \ {selected[c.parent]} \subseteq covered[c.parent])
     IN
       /\ observed' = observed \cup {c.id}
       /\ nodes' = [nodes EXCEPT ![c.child] =
            Node(c.epoch, c.owners, c.identity, c.mode, c.parent, c.scope)]
       /\ children' = [children EXCEPT ![c.parent] = newChildren]
       /\ IF resolves
            THEN /\ selected' = [selected EXCEPT ![c.parent] = c.child]
                 /\ covered' = [covered EXCEPT ![c.parent] = c.refs]
                 /\ resolveSigs' = [resolveSigs EXCEPT ![c.parent] = c.signers]
                 /\ open' = [open EXCEPT ![c.parent] = conflictAfter]
            ELSE /\ selected' = selected
                 /\ covered' = covered
                 /\ resolveSigs' = resolveSigs
                 /\ open' = [open EXCEPT ![c.parent] = conflictAfter]
       /\ IF c.parent = heads[c.scope] /\ children[c.parent] = {}
             /\ CanAuthorize(c.scope)
            THEN /\ heads' = [heads EXCEPT ![c.scope] = c.child]
                 /\ headProof' = [headProof EXCEPT ![c.scope] =
                       <<headProof[c.scope][1] + 1, c.child>>]
                 /\ recoveredIdentity' =
                       IF c.scope = MainScope THEN "" ELSE recoveredIdentity
            ELSE /\ heads' = heads
                 /\ headProof' = headProof
                 /\ UNCHANGED recoveredIdentity
       /\ UNCHANGED <<issued, forkExists>>

RestoreIdentity ==
  /\ Mutation # "Liveness"
  /\ recoveredIdentity' = NodeIdentity(heads[MainScope])
  /\ UNCHANGED <<heads, headProof, nodes, forkExists, issued, observed, children,
                  selected, covered, open, resolveSigs>>

RecoveryBypass ==
  /\ Mutation = "RecoveryBypass"
  /\ recoveredIdentity # Bob
  /\ recoveredIdentity' = Bob
  /\ UNCHANGED <<heads, headProof, nodes, forkExists, issued, observed, children,
                  selected, covered, open, resolveSigs>>

Resolve(c) ==
  /\ c.kind = "Resolution"
  /\ c.id \in issued
  /\ c.id \notin observed
  /\ Epoch(c.child) = -1
  /\ LET newChildren == children[c.parent] \cup {c.child}
         resolves == c.refs = children[c.parent]
         conflictAfter == Cardinality(newChildren) >= 2
            /\ ~(newChildren \ {c.child} \subseteq c.refs)
     IN
       /\ observed' = observed \cup {c.id}
       /\ nodes' = [nodes EXCEPT ![c.child] =
            Node(c.epoch, c.owners, c.identity, c.mode, c.parent, c.scope)]
       /\ children' = [children EXCEPT ![c.parent] = newChildren]
       /\ selected' = [selected EXCEPT ![c.parent] = c.child]
       /\ covered' = [covered EXCEPT ![c.parent] = c.refs]
       /\ resolveSigs' = [resolveSigs EXCEPT ![c.parent] = c.signers]
       /\ open' = [open EXCEPT ![c.parent] = conflictAfter]
       /\ IF resolves
            THEN /\ heads' = [heads EXCEPT ![c.scope] = c.child]
                 /\ headProof' = [headProof EXCEPT ![c.scope] =
                       <<headProof[c.scope][1] + 1, c.child>>]
                 /\ recoveredIdentity' =
                       IF c.scope = MainScope THEN "" ELSE recoveredIdentity
            ELSE /\ heads' = heads
                 /\ headProof' = headProof
                 /\ UNCHANGED recoveredIdentity
       /\ UNCHANGED <<issued, forkExists>>

Fork ==
  /\ Mutation # "Liveness"
  /\ ~forkExists
  /\ forkExists' = TRUE
  /\ nodes' = [nodes EXCEPT ![RootFork] =
       Node(0, {Carol}, Carol, "Majority", "", ForkScope)]
  /\ UNCHANGED <<heads, headProof, recoveredIdentity, issued, observed, children,
                  selected, covered, open, resolveSigs>>

ResolveAny == \E c \in CandidateCerts : Resolve(c)
IssueResolution == Issue(CertById("resolve-R"))

ForgetConflict ==
  /\ Mutation = "ForgetConflict"
  /\ \E p \in AllNodes : open[p]
  /\ LET p == CHOOSE x \in AllNodes : open[x] IN
       open' = [open EXCEPT ![p] = FALSE]
  /\ UNCHANGED <<heads, headProof, nodes, forkExists, recoveredIdentity, issued, observed,
                  children, selected, covered, resolveSigs>>

ReplayStale ==
  /\ Mutation = "StaleReplay"
  /\ heads[MainScope] # RootMain
  /\ heads' = [heads EXCEPT ![MainScope] = RootMain]
  /\ UNCHANGED <<headProof, nodes, forkExists, recoveredIdentity, issued, observed, children,
                  selected, covered, open, resolveSigs>>

ThresholdBypass(c) ==
  /\ Mutation = "Threshold"
  /\ c \in CandidateCerts
  /\ c.id = "bad-one-signature"
  /\ c.parent = heads[MainScope]
  /\ c.epoch = Epoch(c.parent) + 1
  /\ c.signers \subseteq NodeOwners(c.parent)
  /\ Cardinality(c.signers) > 0
  /\ c.child \in AllNodes
  /\ Epoch(c.child) = -1
  /\ c.id \notin issued
  /\ issued' = issued \cup {c.id}
  /\ UNCHANGED <<heads, headProof, nodes, forkExists, recoveredIdentity, observed, children,
                  selected, covered, open, resolveSigs>>

Next ==
  \/ \E c \in CandidateCerts : Issue(c)
  \/ \E c \in CandidateCerts : Observe(c)
  \/ \E c \in CandidateCerts : Resolve(c)
  \/ Fork
  \/ RestoreIdentity
  \/ RecoveryBypass
  \/ ForgetConflict
  \/ ReplayStale
  \/ \E c \in CandidateCerts : ThresholdBypass(c)

TypeOK ==
  /\ heads \in [Scopes -> AllNodes]
  /\ headProof \in [Scopes -> HeadProofs]
  /\ nodes \in [AllNodes -> NodeRecords]
  /\ forkExists \in BOOLEAN
  /\ recoveredIdentity \in {"", Alice, Bob, Carol}
  /\ issued \subseteq {c.id : c \in CandidateCerts}
  /\ observed \subseteq issued
  /\ children \in [AllNodes -> SUBSET AllNodes]
  /\ selected \in [AllNodes -> {""} \cup AllNodes]
  /\ covered \in [AllNodes -> SUBSET AllNodes]
  /\ open \in [AllNodes -> BOOLEAN]
  /\ resolveSigs \in [AllNodes -> SUBSET Owners]

IssuedCertificatesHaveQuorum ==
  \A id \in issued : HasQuorum(CertById(id).signers,
      NodeOwners(CertById(id).parent), NodeMode(CertById(id).parent))

ExactParentEpochAndScope ==
  \A id \in observed :
    LET c == CertById(id) IN
      /\ NodeParent(c.child) = c.parent
      /\ Epoch(c.child) = Epoch(c.parent) + 1
      /\ NodeScope(c.child) = c.scope

ConflictFailsClosed ==
  \A p \in AllNodes : open[p] =>
    /\ Cardinality(children[p]) >= 2
    /\ ~(children[p] \ {selected[p]} \subseteq covered[p])

KnownConflictFailsClosed ==
  \A p \in AllNodes :
    Cardinality(children[p]) >= 2 =>
      (children[p] \ {selected[p]} \subseteq covered[p]) \/ open[p]

ResolutionEvidenceExact ==
  \A id \in observed :
    (CertById(id).kind = "Resolution"
       /\ selected[CertById(id).parent] = CertById(id).child)
      => covered[CertById(id).parent] = CertById(id).refs

HeadHasAuthorizedSelection ==
  \A s \in Scopes : headProof[s][2] = heads[s]

ForkHasSeparateGenesis ==
  forkExists =>
    /\ NodeScope(RootFork) = ForkScope
    /\ Epoch(RootFork) = 0
    /\ NodeOwners(RootFork) = {Carol}
    /\ NodeIdentity(RootFork) = Carol

RecoveryRestoresSelectedIdentity ==
  recoveredIdentity = "" \/ recoveredIdentity = NodeIdentity(heads[MainScope])

Safety == TypeOK /\ IssuedCertificatesHaveQuorum /\ ExactParentEpochAndScope
          /\ ConflictFailsClosed /\ KnownConflictFailsClosed /\ ResolutionEvidenceExact
          /\ HeadHasAuthorizedSelection /\ ForkHasSeparateGenesis
          /\ RecoveryRestoresSelectedIdentity

ObserveAny == \E c \in CandidateCerts : Observe(c) \/ Resolve(c)
Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(IssueResolution) /\ WF_vars(ResolveAny)
           /\ WF_vars(ObserveAny)
ConflictEventuallyResolves ==
  (\E p \in AllNodes : open[p]) ~> ~(\E p \in AllNodes : open[p])

=============================================================================
