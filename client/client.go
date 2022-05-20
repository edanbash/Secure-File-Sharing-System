package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"
	"errors"
	"strings"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).

	// Useful for creating new error messages to return using errors.New("...")

	// Optional.
	_ "strconv"
)

type User struct {
	Username  string
	Salt      []byte
	PKEDecKey userlib.PrivateKeyType
	DSSignKey userlib.PrivateKeyType

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileNode struct {
	OwnerUsername string
	ContentPtr    uuid.UUID
	ParentNode    uuid.UUID
	Children      map[string]uuid.UUID
}

type Invitation struct {
	Sender             string
	Recipient          string
	MasterFileKey      []byte
	ParentFileNodeUUID uuid.UUID
}

type FileContentNode struct {
	ContentUUID     uuid.UUID
	NextContentUUID uuid.UUID
	LastContentUUID uuid.UUID
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Try to retrieve user from Datastore
	hashedUserName := userlib.Hash([]byte(username))
	userUUID, err := uuid.FromBytes(hashedUserName[:16])
	if err != nil {
		return handleUserError("Coudl not get user UUID", err)
	}

	// Checking valid username
	_, ok := userlib.DatastoreGet(userUUID)
	if username == "" || ok {
		return nil, errors.New(strings.ToTitle("Username not valid"))
	}

	// Generating RSA and Signing Keys
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return handleUserError("Couldn't create PKE keys", err)
	}
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return handleUserError("Couldn't create DS keys", err)
	}

	// Storing Public Keys in KeyStore
	PKEEncKeyUUID, err := uuid.FromBytes(hashedUserName[16:32])
	if err != nil {
		return handleUserError("Couldn't generate PKEEncKey UUID", err)
	}

	DSVerifyKeyUUID, err := uuid.FromBytes(hashedUserName[32:48])
	if err != nil {
		return handleUserError("Couldn't generate DSVerifyKey UUID", err)
	}

	userlib.KeystoreSet(PKEEncKeyUUID.String(), PKEEncKey)
	userlib.KeystoreSet(DSVerifyKeyUUID.String(), DSVerifyKey)

	// Creating user struct
	var userdata User
	userdata.Username = username
	userdata.Salt = userlib.RandomBytes(16)
	userdata.PKEDecKey = PKEDecKey
	userdata.DSSignKey = DSSignKey

	// Serialize the user struct
	userBytes, err := json.Marshal(&userdata)
	if err != nil {
		return handleUserError("Error serializing user struct", err)
	}

	// Encrypt the user struct
	userEncKey := userlib.Argon2Key([]byte(password), []byte(userdata.Salt), 32)
	encryptedUserStruct := userlib.SymEnc(userEncKey[:16], userlib.RandomBytes(16), userBytes)

	// HMAC user struct
	userTag, err := userlib.HMACEval(userEncKey[16:], encryptedUserStruct)
	if err != nil {
		return handleUserError("Error genrating HMAC for user", err)
	}

	// Store secure user struct in DataStore
	secureUser := []byte(string(encryptedUserStruct) + string(userTag))
	userlib.DatastoreSet(userUUID, secureUser)

	// Store the intialization salt for user in Datastore
	saltUUID, err := uuid.FromBytes(hashedUserName[48:])
	if err != nil {
		return handleUserError("Couldn't generate salt UUID", err)
	}
	userlib.DatastoreSet(saltUUID, []byte(userdata.Salt))

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Check that username exists
	hashedUserName := userlib.Hash([]byte(username))
	userUUID, err := uuid.FromBytes(hashedUserName[:16])
	secureUser, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("User doesn't exisit"))
	}

	// Retrieve the salt
	saltUUID, err := uuid.FromBytes(hashedUserName[48:])
	if err != nil {
		return handleUserError("Couldn't generate salt UUID", err)
	}
	salt, ok := userlib.DatastoreGet(saltUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("Salt doesnt exist"))
	}

	// Generate the userEncKey with password derived key
	userEncKey := userlib.Argon2Key([]byte(password), salt, 32)

	// Decrypt the user struct
	encryptedUserStruct := secureUser[:len(secureUser)-64]
	userBytes := userlib.SymDec(userEncKey[:16], encryptedUserStruct)

	// Deserialize the user struct
	var userdata User
	err = json.Unmarshal(userBytes, &userdata)
	if err != nil {
		return handleUserError("Cannot deserialize user ", err)
	}

	// Compare derived and retrieved HMAC Tag for user
	retrievedUserTag := secureUser[len(secureUser)-64:]
	derivedUserTag, err := userlib.HMACEval(userEncKey[16:], encryptedUserStruct)
	if err != nil {
		return handleUserError("Could not generate HMAC Tag", err)
	}

	userTagsEqual := userlib.HMACEqual(derivedUserTag, retrievedUserTag)
	if !userTagsEqual {
		return handleUserError("User HMACs do not match", nil)
	}

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Generate the fileNodeUUID
	fileNodeUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename))[:16])
	if err != nil {
		return handleError("Could not get fileNodeUUID", err)
	}

	var fileNode FileNode
	var masterFileKey []byte
	var fileContentNode FileContentNode

	_, ok := userlib.DatastoreGet(fileNodeUUID)
	// If FileNode already exists
	if ok {
		// Retrieve masterFileKey from Datastore
		_, masterFileKey, err = getFileAndKey(userdata, filename)
		if err != nil {
			return handleError("Could not retrieve masterFileKey", err)
		}

		// Retrieve the fileNode using the masterFileKey
		fileNode, err := getFileNode(fileNodeUUID, masterFileKey, userdata.Username)
		if err != nil {
			return handleError("Couldnt retrieve fileNode", err)
		}

		// Retrieve the fileContentNode using the masterFileKey
		fileContentNodeBytes, err := retVerifyDec(fileNode.ContentPtr, masterFileKey, "list")
		if err != nil {
			return handleError("Couldnt retrieve fileContentNodeBytes", err)
		}
		err = json.Unmarshal(fileContentNodeBytes, &fileContentNode)
		if err != nil {
			return handleError("Couldn't unmarshal fileContentNode", err)
		}

	} else {
		// Creating new fileNode
		fileNode.OwnerUsername = userdata.Username
		fileNode.ContentPtr = uuid.New()
		fileNode.Children = make(map[string]uuid.UUID)
		fileNode.ParentNode = uuid.UUID{}

		// Generate the lockboxUUID
		lockBoxUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + fileNodeUUID.String()))[:16])
		if err != nil {
			return handleError("Could not get lockBoxUUID", err)
		}

		// Generate, Encrypt, and Store masterFileKey in the lockbox
		masterFileKey = userlib.RandomBytes(16)
		_, err = publicEnc(userdata.Username, lockBoxUUID, "lockbox", masterFileKey)
		if err != nil {
			return handleError("Could not store masterFileKey", err)
		}

		//Store new fileNode in Datastore
		err = secureStore(fileNodeUUID, fileNode, masterFileKey, userdata.Username+"node")
		if err != nil {
			return handleError("Could not store fileNode", err)
		}

		// Creating new fileContentNode
		fileContentNode.ContentUUID = uuid.New()
	}

	// Set the nextContentUUID to null and lastContentUUID to itself
	fileContentNode.NextContentUUID = uuid.UUID{}
	fileContentNode.LastContentUUID = fileNode.ContentPtr

	// Storing secure fileContentNode in Datastore
	secureStore(fileNode.ContentPtr, fileContentNode, masterFileKey, "list")

	// Creating secure fileContent
	secureFileContent, err := EncThenHMAC(masterFileKey, "content", content)
	if err != nil {
		return handleError("Could not encrypt fileContent", err)
	}

	//Store newly appended content in Datastore
	userlib.DatastoreSet(fileContentNode.ContentUUID, secureFileContent)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Retrieve fileNodeUUID and masterFileKey
	fileNodeUUID, masterFileKey, err := getFileAndKey(userdata, filename)
	if err != nil {
		return handleError("Could not retrieve masterFileKey", err)
	}

	// Retrieve the fileNode using the masterFileKey
	fileNode, err := getFileNode(fileNodeUUID, masterFileKey, userdata.Username)
	if err != nil {
		return handleError("Couldnt retrieve fileNodeBytes", err)
	}

	//Retrive the firstContentNode from the fileContentList
	firstContentNodeBytes, err := retVerifyDec(fileNode.ContentPtr, masterFileKey, "list")
	if err != nil {
		return handleError("Couldn't retrieve firstContentNode", err)
	}
	var firstContentNode FileContentNode
	err = json.Unmarshal(firstContentNodeBytes, &firstContentNode)
	if err != nil {
		return handleError("Could not unmarshal firstContentNode", err)
	}

	// Retrieve the lastContentNode from the fileContentList
	lastContentNodeBytes, err := retVerifyDec(firstContentNode.LastContentUUID, masterFileKey, "list")
	if err != nil {
		return handleError("Couldn't retrieve lastContentNode", err)
	}
	var lastContentNode FileContentNode
	err = json.Unmarshal(lastContentNodeBytes, &lastContentNode)
	if err != nil {
		return handleError("Could not unmarshal lastContentNode", err)
	}

	//Create and store newFileNodeContent struct
	var newFileContentNode FileContentNode
	newFileContentNodeUUID := uuid.New()
	newFileContentNode.ContentUUID = uuid.New()
	newFileContentNode.NextContentUUID = uuid.UUID{}
	secureStore(newFileContentNodeUUID, newFileContentNode, masterFileKey, "list")

	// Creating and secure new content
	secureFileContent, err := EncThenHMAC(masterFileKey, "content", content)
	if err != nil {
		return handleError("Could not encrypt fileContent", err)
	}
	userlib.DatastoreSet(newFileContentNode.ContentUUID, secureFileContent)

	if firstContentNode.NextContentUUID == uuid.Nil {
		firstContentNode.NextContentUUID = newFileContentNodeUUID
		firstContentNode.LastContentUUID = newFileContentNodeUUID
		secureStore(fileNode.ContentPtr, firstContentNode, masterFileKey, "list")
	} else {
		//Update and secureStore previous last fileNodeContent
		lastContentNode.NextContentUUID = newFileContentNodeUUID
		secureStore(firstContentNode.LastContentUUID, lastContentNode, masterFileKey, "list")

		// Update the lastContentNode pointer to new node
		firstContentNode.LastContentUUID = newFileContentNodeUUID
		secureStore(fileNode.ContentPtr, firstContentNode, masterFileKey, "list")
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Retrieve fileNodeUUID and masterFileKey
	fileNodeUUID, masterFileKey, err := getFileAndKey(userdata, filename)
	if err != nil {
		return handleByteError("Could not retrieve masterFileKey", err)
	}

	// Retrieve the fileNode using the masterFileKey
	fileNode, err := getFileNode(fileNodeUUID, masterFileKey, userdata.Username)
	if err != nil {
		return handleByteError("Couldnt retrieve fileNodeBytes", err)
	}

	// Retrieving and decrypting all fileContent
	fullContent := []byte{}
	var currContentNode FileContentNode
	currContentNodePtr := fileNode.ContentPtr
	for currContentNodePtr.String() != "00000000-0000-0000-0000-000000000000" {
		// Retrieve the currContentNode with masterFileKey
		currContentNodeBytes, err := retVerifyDec(currContentNodePtr, masterFileKey, "list")
		if err != nil {
			return handleByteError("Couldn't retrieve currContentNode", err)
		}
		err = json.Unmarshal(currContentNodeBytes, &currContentNode)
		if err != nil {
			return handleByteError("Could not unmarshal currContentNode", err)
		}

		// Retrieve the currContent with masterFileKey
		currContent, err := retVerifyDec(currContentNode.ContentUUID, masterFileKey, "content")
		if err != nil {
			return handleByteError("Couldn't retrieve currContent", err)
		}
		fullContent = append(fullContent, currContent...)
		currContentNodePtr = currContentNode.NextContentUUID
	}
	return fullContent, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// Make sure recipientUsername exists
	rechashedUserName := userlib.Hash([]byte(recipientUsername))
	userUUID, err := uuid.FromBytes(rechashedUserName[:16])
	if err != nil {
		return handleUUIDError("Coudl not get user UUID", err)
	}
	_, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("recipient doesnt exisit"))
	}

	// Retrieve fileNodeUUID and masterFileKey
	fileNodeUUID, masterFileKey, err := getFileAndKey(userdata, filename)
	if err != nil {
		return handleUUIDError("Could not retrieve masterFileKey", err)
	}

	//Make sure fileNodeUUID exisit
	_, ok = userlib.DatastoreGet(fileNodeUUID)
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("FileName doesnt exisit"))
	}

	// Creating the invitation
	var invitation Invitation
	invitation.Sender = userdata.Username
	invitation.Recipient = recipientUsername
	invitation.MasterFileKey = masterFileKey
	invitation.ParentFileNodeUUID = fileNodeUUID

	// Serialize the invitation
	invitationBytes, err := json.Marshal(&invitation)
	if err != nil {
		return handleUUIDError("Error serializing invitation", err)
	}

	// Sign the invitation
	signature, err := userlib.DSSign(userdata.DSSignKey, invitationBytes)
	if err != nil {
		return handleUUIDError("Error signing invitation", err)
	}
	signedInvitationBytes := append(invitationBytes, signature...)

	//Publicly Encypt the invitation with recipent's publicKey
	invitationUUID := uuid.New()
	secureInvitation, err := publicEnc(recipientUsername, invitationUUID, "invitation", signedInvitationBytes)
	if err != nil {
		return handleUUIDError("Couldn't encrypt invitation", err)
	}

	// Store secure invitation in DataStore
	userlib.DatastoreSet(invitationUUID, secureInvitation)

	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Make sure invitation exisit
	if invitationPtr == uuid.Nil {
		return errors.New(strings.ToTitle("Invitation doesn't exisit"))
	}
	//Retrive the invitation from Datastore
	signedInvitationBytes, err := publicDec(userdata, invitationPtr, "invitation")
	if err != nil {
		return errors.New(strings.ToTitle("Invitation doesn't exisit"))
	}

	// Deserialize the invitation
	var invitation Invitation
	invitationBytes := signedInvitationBytes[:len(signedInvitationBytes)-256]
	err = json.Unmarshal(invitationBytes, &invitation)
	if err != nil {
		return handleError("Error deserializing invitation", err)
	}

	// Retrieve the DSVerifyKey of recipient
	hashedUsername := userlib.Hash([]byte(invitation.Sender))
	DSVerifyKeyUUID, err := uuid.FromBytes(hashedUsername[32:48])
	if err != nil {
		return handleError("Couldn't generate PKEEncKeyUUID", err)
	}
	DSVerifyKey, ok := userlib.KeystoreGet(DSVerifyKeyUUID.String())
	if !ok {
		return errors.New(strings.ToTitle("Could not find DS Verify Key"))
	}

	// Verify the Signature on the invitation
	signature := signedInvitationBytes[len(signedInvitationBytes)-256:]
	err = userlib.DSVerify(DSVerifyKey, invitationBytes, signature)
	if err != nil {
		return handleError("Could not verify signature", err)
	}

	//Generate the fileNodeUUID
	fileNodeUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename))[:16])
	if err != nil {
		return handleError("Could not get fileNodeUUID", err)
	}

	// Check that filename does not exist in personal namespace
	_, ok = userlib.DatastoreGet(fileNodeUUID)
	if ok {
		return errors.New(strings.ToTitle("Filename already exists"))
	}

	// Generate the lockBoxUUID
	lockBoxUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + fileNodeUUID.String()))[:16])
	if err != nil {
		return handleError("Could not get lockBoxUUID", err)
	}

	// Securely store the passed in masterFileKey
	_, err = publicEnc(userdata.Username, lockBoxUUID, "lockbox", invitation.MasterFileKey)
	if err != nil {
		return handleError("Could not store masterFileKey", err)
	}

	// Retrieve the parentFileNode using the masterFileKey
	parentFileNode, err := getFileNode(invitation.ParentFileNodeUUID, invitation.MasterFileKey, invitation.Sender)
	if err != nil {
		return handleError("Couldnt retrieve parentFileNode", err)
	}

	// Creating new fileNode
	var fileNode FileNode
	fileNode.OwnerUsername = parentFileNode.OwnerUsername
	fileNode.ContentPtr = parentFileNode.ContentPtr
	fileNode.Children = make(map[string]uuid.UUID)
	fileNode.ParentNode = invitation.ParentFileNodeUUID

	//Checking sender is valid
	if invitation.Sender != senderUsername {
		return errors.New(strings.ToTitle("Sender is not correct"))
	}
	//Store new fileNode in Datastore
	err = secureStore(fileNodeUUID, fileNode, invitation.MasterFileKey, userdata.Username+"node")
	if err != nil {
		return handleError("Could not store fileNode", err)
	}

	// Update Children in Parent FileNode
	parentFileNode.Children[userdata.Username] = fileNodeUUID

	//Store updated parentFileNode in Datastore
	err = secureStore(invitation.ParentFileNodeUUID, parentFileNode, invitation.MasterFileKey, invitation.Sender+"node")
	if err != nil {
		return handleError("Could not store parentFileNode", err)
	}
	userlib.DatastoreDelete(invitationPtr)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Retrieve fileNodeUUID and masterFileKey from Datastore
	fileNodeUUID, masterFileKey, err := getFileAndKey(userdata, filename)
	if err != nil {
		return handleError("Could not retrieve masterFileKey", err)
	}

	// Retrieve the fileNode using the masterFileKey
	fileNode, err := getFileNode(fileNodeUUID, masterFileKey, userdata.Username)
	if err != nil {
		return handleError("Couldnt retrieve fileNode", err)
	}

	// Check that current user is owner
	if fileNode.OwnerUsername != userdata.Username {
		return errors.New(strings.ToTitle("Current User does not own file"))
	}

	// Check that recipient is in children list
	if _, ok := fileNode.Children[recipientUsername]; !ok {
		return errors.New(strings.ToTitle("Recipient is not in child list"))
	}

	// Retrieve the childFileNode using the masterFileKey
	childFileNode, err := getFileNode(fileNode.Children[recipientUsername], masterFileKey, recipientUsername)
	if err != nil {
		return handleError("Couldnt retrieve childFileNode", err)
	}

	// Delete all the childrenFileNodes
	err = deleteChildren(childFileNode, fileNode.Children[recipientUsername], masterFileKey)
	if err != nil {
		return handleError("Could not delete children", err)
	}

	// Remove childFileNode from owner's children
	delete(fileNode.Children, recipientUsername)

	// Generate a new masterFileKey
	newMasterFileKey := userlib.RandomBytes(16)

	// Update tree's lockbox and secureStore fileNodes with new masterFileKey
	err = updateChildren(fileNode, fileNodeUUID, userdata.Username, newMasterFileKey, masterFileKey)
	if err != nil {
		return handleError("Could not update children", err)
	}

	// Re-encrypt all the fileContentNodes in the FileContentNodeList and actual content
	var currContentNode FileContentNode
	currContentNodePtr := fileNode.ContentPtr

	for currContentNodePtr != uuid.Nil {
		// Retrieve the currContentNode with old masterFileKey
		currContentNodeBytes, err := retVerifyDec(currContentNodePtr, masterFileKey, "list")
		if err != nil {
			return handleError("Couldn't retrieve currContentNode", err)
		}
		err = json.Unmarshal(currContentNodeBytes, &currContentNode)
		if err != nil {
			return handleError("Could not unmarshal currContentNode", err)
		}

		// Retrieve the currContent with old masterFileKey
		currContent, err := retVerifyDec(currContentNode.ContentUUID, masterFileKey, "content")
		if err != nil {
			return handleError("Couldn't retrieve currContent", err)
		}

		// Update currContentNode.ContentUUID
		currContentNode.ContentUUID = uuid.New()

		// Securely store the content with newMasterFileKey
		secureFileContent, err := EncThenHMAC(newMasterFileKey, "content", currContent)
		if err != nil {
			return handleError("Could not encrypt fileContent", err)
		}
		userlib.DatastoreSet(currContentNode.ContentUUID, secureFileContent)

		// Securely store the fileContentNode with newMasterFileKey
		err = secureStore(currContentNodePtr, currContentNode, newMasterFileKey, "list")
		if err != nil {
			return handleError("Could not re-encrypt the conent with new masterFileKey", err)
		}
		currContentNodePtr = currContentNode.NextContentUUID
	}
	return nil

}

//Recursively Deleting FileNode and FileNode's children
func deleteChildren(fileNode FileNode, fileNodeUUID uuid.UUID, masterFileKey []byte) (err error) {
	// call
	userlib.DatastoreDelete(fileNodeUUID)
	for username, childUUID := range fileNode.Children {
		// Retrieve the childFileNode using the masterFileKey
		childFileNode, err := getFileNode(childUUID, masterFileKey, username)
		if err != nil {
			return handleError("Couldnt retrieve childFileNode", err)
		}
		deleteChildren(childFileNode, childUUID, masterFileKey)
	}
	return nil
}

func updateChildren(fileNode FileNode, fileNodeUUID uuid.UUID, username string, newMasterFileKey []byte, oldMasterFileKey []byte) (err error) {
	//Generate the fileNode's lockbox
	lockBoxUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + fileNodeUUID.String()))[:16])
	if err != nil {
		return handleError("Could not get lockBoxUUID", err)
	}

	//Update fileNode's lockbox
	_, err = publicEnc(username, lockBoxUUID, "lockbox", newMasterFileKey)
	if err != nil {
		return handleError("Could not encrypt new lockBox", err)
	}

	// secureStore fileNode with new masterFileKey
	err = secureStore(fileNodeUUID, fileNode, newMasterFileKey, username+"node")
	if err != nil {
		return handleError("Could not secureStore fileNode", err)
	}

	//Loop through children
	for childUsername, childUUID := range fileNode.Children {
		// Retrieve the childFileNode using the masterFileKey
		childFileNode, err := getFileNode(childUUID, oldMasterFileKey, childUsername)
		if err != nil {
			return handleError("Couldnt retrieve childFileNode", err)
		}
		updateChildren(childFileNode, childUUID, childUsername, newMasterFileKey, oldMasterFileKey)
	}

	return nil
}

// Returns an encrypted and tagged message given a sourceKey and purpose
func EncThenHMAC(sourceKey []byte, purpose string, plainText []byte) (secureMsg []byte, err error) {
	// Symetrically encrypts the msg
	encKey, err := userlib.HashKDF(sourceKey[:16], []byte(purpose+"Enc"))
	if err != nil {
		return handleByteError("Could not generate EncKey for "+purpose, err)
	}
	cipherText := userlib.SymEnc(encKey[:16], userlib.RandomBytes(16), plainText)

	// Generate the HMAC Tag
	HMACKey, err := userlib.HashKDF(sourceKey[:16], []byte(purpose+"HMAC"))
	if err != nil {
		return handleByteError("Could not generate HMAC key for "+purpose, err)
	}
	HMACTag, err := userlib.HMACEval(HMACKey[:16], cipherText)
	if err != nil {
		return handleByteError("Could not generate HMAC Tag for "+purpose, err)
	}

	return append(cipherText, HMACTag...), nil
}

// Securely stores an object in Datastore given a sourceKey and purpose
func secureStore(keyUUID uuid.UUID, v interface{}, sourceKey []byte, purpose string) (err error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return handleError("Couldn't serialize data", err)
	}
	secureBytes, err := EncThenHMAC(sourceKey, purpose, bytes)
	if err != nil {
		return handleError("Couldn't encrypt bytes", err)
	}
	userlib.DatastoreSet(keyUUID, secureBytes)
	return nil
}

// Retrives, verifies, and decrypts an object in Datastore given a sourceKey and purpose
func retVerifyDec(keyUUID uuid.UUID, sourceKey []byte, purpose string) (bytes []byte, err error) {
	// Retrieves the encrypted JSON from Datastore
	secureMsg, ok := userlib.DatastoreGet(keyUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("Doesn't exisit"))
	}

	// Verifies then Decrypts the secureMsg
	plainText, err := VerifyThenDec(sourceKey, purpose, secureMsg)
	if err != nil {
		return handleByteError("Could not verify or decrypt data", err)
	}

	return plainText, nil
}

// Verifies and decrypts a secureMsg given a sourceKey and purpose
func VerifyThenDec(sourceKey []byte, purpose string, secureMsg []byte) (result []byte, err error) {
	// Verifies the HMAC Tag has not been changed
	retrievedTag := secureMsg[len(secureMsg)-64:]
	cipherText := secureMsg[:len(secureMsg)-64]
	HMACKey, err := userlib.HashKDF(sourceKey, []byte(purpose+"HMAC"))
	if err != nil {
		return handleByteError("Could not generate HMAC key for "+purpose, err)
	}
	derivedTag, err := userlib.HMACEval(HMACKey[:16], cipherText)
	if err != nil {
		return handleByteError("Could not generate HMAC Tag for "+purpose, err)
	}
	tagsEqual := userlib.HMACEqual(derivedTag, retrievedTag)
	if !tagsEqual {
		return handleByteError("Tags are not equal for "+purpose, err)
	}

	// Decrypts the ciphertext
	encKey, err := userlib.HashKDF(sourceKey, []byte(purpose+"Enc"))
	if err != nil {
		return handleByteError("Could not generate EncKey for "+purpose, err)
	}
	plainText := userlib.SymDec(encKey[:16], cipherText)
	if err != nil {
		return handleByteError("Could not decrypt the data", err)
	}

	return plainText, nil
}

// Encrypts and stores an entry in DataStore entry using PKEEncKey for user
func publicEnc(username string, keyUUID uuid.UUID, purpose string, data []byte) (ret []byte, err error) {
	// Retrieve the PKEEncKey for given username
	hashedUserName := userlib.Hash([]byte(username))
	PKEEncKeyUUID, err := uuid.FromBytes(hashedUserName[16:32])
	if err != nil {
		return handleByteError("Could not generate PKEEncKeyUUID", err)
	}
	PKEEncKey, ok := userlib.KeystoreGet(PKEEncKeyUUID.String())
	if !ok {
		return nil, errors.New(strings.ToTitle("Key doesn't exisit"))
	}

	// Generate and publicly encrypt random symKey
	symKey := userlib.RandomBytes(16)
	encSymKey, err := userlib.PKEEnc(PKEEncKey, symKey)
	if err != nil {
		return handleByteError("Could not publicly encrypt symKey", err)
	}

	// Encrypt and HMAC with symKey and attach encSymKey
	secureMsg, err := EncThenHMAC(symKey, purpose, data)
	if err != nil {
		return handleByteError("Could not Encrypt Data "+purpose, err)
	}
	secureData := append(encSymKey, secureMsg...)

	// Store secure data in DataStore
	userlib.DatastoreSet(keyUUID, secureData)

	return secureData, nil
}

// Decrypts a DataStore entry using PKEDecKey for user
func publicDec(userdata *User, keyUUID uuid.UUID, purpose string) (msg []byte, err error) {
	// Retrieve encryptedData from Datastore
	encryptedData, ok := userlib.DatastoreGet(keyUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("Data doesn't exisit"))
	}

	// Decrypts symKey using with user's PKEDecKey
	if len(encryptedData) < 256 {
		return nil, errors.New(strings.ToTitle("Data has been tampered with"))
	}
	encSymKey := encryptedData[:256]
	symKey, err := userlib.PKEDec(userdata.PKEDecKey, encSymKey)
	if err != nil {
		return handleByteError("Cannot decrypt symKey", err)
	}

	// Verifies and decrypts the actual data
	encMessage := encryptedData[256:]
	plainText, err := VerifyThenDec(symKey, purpose, encMessage)
	if err != nil {
		return handleByteError("Cannot verify or decrypt for "+purpose, err)
	}
	return plainText, nil
}

// Return the fileNodeUUID and masterFileKey for given user and filename
func getFileAndKey(userdata *User, filename string) (fileLocation uuid.UUID, key []byte, err error) {
	//Generate the fileNodeUUID
	fileNodeUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename))[:16])
	if err != nil {
		return handleUUIDByteError("Could not get fileNodeUUID", err)
	}

	// Generate the lockBoxUUID
	lockBoxUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + fileNodeUUID.String()))[:16])
	if err != nil {
		return handleUUIDByteError("Could not get lockBoxUUID", err)
	}

	//Retrieving, verifying, and Decrypting masterFileKey
	masterFileKey, err := publicDec(userdata, lockBoxUUID, "lockbox")
	if err != nil {
		return handleUUIDByteError("Could not retrieve masterFileKey", err)
	}

	return fileNodeUUID, masterFileKey, nil
}

// Return the unserialized fileNode for given user
func getFileNode(fileNodeUUID uuid.UUID, masterFileKey []byte, username string) (f FileNode, e error) {
	var fileNode FileNode
	fileNodeBytes, err := retVerifyDec(fileNodeUUID, masterFileKey, username+"node")
	if err != nil {
		return handleFileError("Couldnt retrieve fileNodeBytes", err)
	}
	err = json.Unmarshal(fileNodeBytes, &fileNode)
	if err != nil {
		return handleFileError("Could not unmarshal fileNode", err)
	}
	return fileNode, nil
}

// Error Handling Helper Functions
func handleError(msg string, err error) (e error) {
	userlib.DebugMsg(msg)
	return err
}

func handleUserError(msg string, err error) (userdataptr *User, e error) {
	userlib.DebugMsg(msg)
	return nil, err
}

func handleByteError(msg string, err error) (bytes []byte, e error) {
	userlib.DebugMsg(msg)
	return nil, err
}

func handleUUIDError(msg string, err error) (u uuid.UUID, e error) {
	userlib.DebugMsg(msg)
	return uuid.UUID{}, err
}

func handleUUIDByteError(msg string, err error) (u uuid.UUID, m []byte, e error) {
	userlib.DebugMsg(msg)
	return uuid.UUID{}, nil, err
}

func handleFileError(msg string, err error) (f FileNode, e error) {
	userlib.DebugMsg(msg)
	return FileNode{}, err
}
