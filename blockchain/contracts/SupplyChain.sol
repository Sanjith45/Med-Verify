// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SupplyChain {
    address public owner;
    
    struct Product {
        uint id;
        string name;
        address manufacturer;
        address distributor;
        bool isAccepted;
    }

    uint public productCounter = 0;
    mapping(uint => Product) public products;
    
    event ProductRequested(uint indexed id, address indexed distributor);
    event ProductAccepted(uint indexed id, address indexed manufacturer, address indexed distributor);

    constructor() {
        owner = msg.sender;
    }

    function requestProduct(string memory _name) public {
        productCounter++;
        products[productCounter] = Product(productCounter, _name, address(0), msg.sender, false);
        emit ProductRequested(productCounter, msg.sender);
    }

    function acceptRequest(uint _productId) public {
        require(products[_productId].distributor != address(0), "Product request does not exist");
        require(products[_productId].manufacturer == msg.sender || products[_productId].manufacturer == address(0), "Already accepted");


        products[_productId].manufacturer = msg.sender;
        products[_productId].isAccepted = true;

        emit ProductAccepted(_productId, msg.sender, products[_productId].distributor);
    }
}
