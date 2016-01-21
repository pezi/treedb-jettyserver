/*
* (C) Copyright 2014,2016 Peter Sauer (http://treedb.at/).
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 */
package at.treedb;

import java.awt.Desktop;
import java.awt.Font;
import java.awt.Image;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

import javax.swing.ImageIcon;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;


@SuppressWarnings("serial")
public class HelpWindow extends JFrame {
    public HelpWindow(String icon,String title, String html, String... images) {
        super(title);
        
        if(icon != null) {
            ArrayList<Image> iconList = new ArrayList<Image>();
            iconList.add(new ImageIcon(getClass().getResource("/images/" + icon)).getImage());
            setIconImages(iconList);
        }
        
        setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        String htmlStr = null;
        try {
            InputStream in = getClass().getResourceAsStream("/html/" + html); 
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            String line;
            StringBuffer b = new StringBuffer();
            while ((line = reader.readLine()) != null) {
                b.append(line);
                b.append('\n');
            }
            htmlStr = b.toString();
            for (String img : images) {
                String imgPath = getClass().getResource("/images/" + img).toString();
                htmlStr = htmlStr.replace("$" + img +"$", imgPath);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        // Set up the content pane.
        JTextPane htmlPane = new  JTextPane();
        htmlPane.setContentType("text/html");
        htmlPane.setText(htmlStr);
        htmlPane.setCaretPosition(0);
        htmlPane.addHyperlinkListener(new HyperlinkListener() {
             @Override
             public void hyperlinkUpdate(HyperlinkEvent hle) {
                 System.out.println("hello");
                 if (HyperlinkEvent.EventType.ACTIVATED.equals(hle.getEventType())) {
                     System.out.println(hle.getURL());
                     Desktop desktop = Desktop.getDesktop();
                     try {
                         desktop.browse(hle.getURL().toURI());
                     } catch (Exception ex) {
                         ex.printStackTrace();
                     }
                 }
             }
         });

        this.getContentPane().add(new JScrollPane(htmlPane));
        pack();
        setResizable(true);
        setVisible(true);
    }
}
