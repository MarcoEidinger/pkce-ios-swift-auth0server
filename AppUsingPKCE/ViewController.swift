//
//  ViewController.swift
//  AppUsingPKCE
//
//  Created by Eidinger, Marco on 12/16/21.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    @IBAction func signIn(_ sender: Any) {
        let alert = UIAlertController(
            title: "Result",
            message: "TODO",
            preferredStyle: .alert)
        alert.addAction(.init(title: "Ok", style: .default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

}

