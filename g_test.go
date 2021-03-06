package gosrp

import (
	"fmt"
	"testing"
)

// -----------------------------------------------------------------------------------------------------------------------------------------------
// Test dummy return constant - this is really just to setup the testing process.

func Test_GsSrp1(t *testing.T) {

	// /api/srp_login - setup and pull back "salt" + t,r randoms
	// save state undr 'r' random from this point forward
	sss := GoSrpNew("alice", 2048)
	sss.Setup("9ecd61c8a7364fda5961043a877f911db7d624c12a9e19068c4b89ccb48a9b81fa6427e16833d5bdadca6a28d164e6e4f8be91030923e6bf4075fb53e5a89e8627a96dca8c48030fdf5afd7451a581acae917f225105688e030eafc82c4a3731d287e12f8483ccd207e03ff625b8c77da8da0ad7e47376d4e365933441ebe6bb4fbdb1206a327de21a651a567d84d51ecde4d7ec5b16dce0d7bea7967ecba1cad203bedbb6c643e400d42a839a9fa2c18732df96cc81688a7c22ffd90b1f77a49ee1c502a847b18d24bb6996afe6633b50407a94bf8c0fcfead64ae0585e1dfe709a2b278b2af3c5f2e39363bb222faa5877e43b878fd17302931ed40fad34bc", "265433c66bb3009468df07ecf733e147c8f4f7d90b278e2350f6c95143a6f53a")

	sss.TestDump1()
	if db8 {
		fmt.Printf("=================================================\n")
	}

	// Simulate client generateing A
	// Do this on the client side sending bac, 'A' and 'r'
	A := sss.CalculateA()
	sss.TestDump2()

	if db8 {
		fmt.Printf("=================================================\n")
	}

	// Send back 'B', 'u' to client
	sss.IssueChallenge(A)
	sss.TestDump3()

	ClientM1 := sss.XM1_s // Pretent a client call happend and we get back M1

	if db8 {
		fmt.Printf("=================================================\n")
	}
	auth, m2 := sss.CalculateM2(ClientM1)
	_ = m2 // m2 should be sent back to client for it to validate server key.
	if db8 {
		fmt.Printf("ClientM1= [%s] (Simulated Client M)\n", ClientM1)
	}
	sss.TestDump4()

	if db8 {
		fmt.Printf("=================================================\n")
		if auth {
			fmt.Printf("Validation Successful\n")
		} else {
			fmt.Printf("FAILED - to login\n")
		}
	}

	if db8 {
		fmt.Printf("=================================================\n")
	}
	if sss.Salt.HexString() != "265433c66bb3009468df07ecf733e147c8f4f7d90b278e2350f6c95143a6f53a" {
		t.Errorf("Error %d, salt did not get convert to Big correctly\n", 100)
	}

	if !auth {
		t.Errorf("Error - Failed to authorize\n")
	}
}
